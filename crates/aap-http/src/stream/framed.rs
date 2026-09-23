use aap_types::{
    ErrorCode, Result,
    stream::{
        self, Decoder, Frame, Sender, Sequence,
        service::{ApplicationIo, AttachmentError},
    },
};
use bytes::Bytes;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

pub(super) trait WireIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> WireIo for T {}

pub(super) struct Control(Arc<Mutex<State>>);
struct Attachment(Arc<Mutex<State>>);
struct State {
    io: Option<Box<dyn WireIo>>,
    sequence: Sequence,
    decoder: Decoder,
    pending: Bytes,
    scratch: Box<[u8]>,
    start: usize,
    filled: usize,
    max_data: usize,
    output: Option<Output>,
    failed: Option<AttachmentError>,
    retired: bool,
}
struct Output {
    header: [u8; 5],
    written: usize,
    remaining: usize,
    end: bool,
}

/// OPENED must already have been fully written. The engine must own the payload
/// reservation before constructing this channel; no application queue is spawned.
pub(super) fn channel(
    io: Box<dyn WireIo>,
    request: stream::Open,
    opened: stream::Opened,
) -> Result<(Control, Box<dyn ApplicationIo>)> {
    let max_data = opened.max_data_bytes as usize;
    let mut sequence = Sequence::new(request)?;
    sequence.accept(Sender::Daemon, &Frame::Opened(opened))?;
    let state = Arc::new(Mutex::new(State {
        io: Some(io),
        sequence,
        decoder: Decoder::default(),
        pending: Bytes::new(),
        scratch: vec![0; 1024].into_boxed_slice(),
        start: 0,
        filled: 0,
        max_data,
        output: None,
        failed: None,
        retired: false,
    }));
    Ok((Control(state.clone()), Box::new(Attachment(state))))
}
impl Control {
    /// Poll outside the engine's application callbacks. This keeps post-END
    /// bytes/EOF observable while the engine waits only on the opposite direction.
    pub fn fault(&self, cx: &mut Context<'_>) -> Option<AttachmentError> {
        match self.0.lock() {
            Ok(mut state) => state.watch_end(cx),
            Err(_) => Some(AttachmentError::InternalError),
        }
    }
    pub async fn finish(self, terminal: &stream::Terminal) -> Result<()> {
        let frame = Frame::Terminal(terminal.clone());
        let encoded = frame.encode()?;
        let mut io = {
            let mut state = self.0.lock().map_err(|_| ErrorCode::InternalError)?;
            if !state.retired
                || state.output.as_ref().is_some_and(|output| {
                    output.written != 0 || terminal.cause == stream::Cause::OrderlyEnd
                })
            {
                return Err(ErrorCode::ResultUnavailable.into());
            }
            // An entirely unwritten pending frame may be discarded. An already
            // started header/payload may never be replaced by a terminal frame.
            state.output = None;
            state.sequence.accept(Sender::Daemon, &frame)?;
            state.io.take().ok_or(ErrorCode::ResultUnavailable)?
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            io.write_all(&encoded.header).await?;
            io.write_all(&encoded.payload).await?;
            io.flush().await
        })
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?
        .map_err(|_| ErrorCode::ResultUnavailable.into())
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.io.take();
        state.retire();
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retire();
    }
}
impl ApplicationIo for Attachment {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        let Ok(mut state) = self.0.lock() else {
            return Poll::Ready(Err(AttachmentError::InternalError));
        };
        let result = state.read(cx, buffer);
        state.capture(result)
    }
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        let Ok(mut state) = self.0.lock() else {
            return Poll::Ready(Err(AttachmentError::InternalError));
        };
        let result = state.write(cx, bytes);
        state.capture(result)
    }
    fn poll_send_end(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), AttachmentError>> {
        let Ok(mut state) = self.0.lock() else {
            return Poll::Ready(Err(AttachmentError::InternalError));
        };
        let result = state.end(cx);
        state.capture(result)
    }
}
impl State {
    fn capture<T>(
        &mut self,
        result: Poll<std::result::Result<T, AttachmentError>>,
    ) -> Poll<std::result::Result<T, AttachmentError>> {
        if let Poll::Ready(Err(error)) = &result {
            self.failed.get_or_insert(*error);
        }
        result
    }
    fn retire(&mut self) {
        // Release all payload when the engine releases its capacity reservation.
        // Keep only bounded protocol metadata and the final-control socket owner.
        self.retired = true;
        self.pending = Bytes::new();
        self.decoder = Decoder::default();
        self.scratch = Box::new([]);
        self.start = 0;
        self.filled = 0;
    }
    fn check(&self) -> std::result::Result<(), AttachmentError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.retired || self.io.is_none() {
            return Err(AttachmentError::AttachmentLost);
        }
        Ok(())
    }
    fn watch_end(&mut self, cx: &mut Context<'_>) -> Option<AttachmentError> {
        if self.failed.is_some() {
            return self.failed;
        }
        if self.retired || !self.sequence.ended(Sender::Agent) {
            return None;
        }
        let error = if self.start < self.filled {
            Some(AttachmentError::InvalidFrame)
        } else if let Some(io) = &mut self.io {
            let mut byte = [0];
            let mut buffer = ReadBuf::new(&mut byte);
            match Pin::new(io).poll_read(cx, &mut buffer) {
                Poll::Pending => None,
                Poll::Ready(Ok(())) if !buffer.filled().is_empty() => {
                    Some(AttachmentError::InvalidFrame)
                }
                _ => Some(AttachmentError::AttachmentLost),
            }
        } else {
            Some(AttachmentError::AttachmentLost)
        };
        self.failed = error;
        error
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        self.check()?;
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Bound parsing/syscalls in addition to the engine's bounded I/O polls.
        for _ in 0..4 {
            if !self.pending.is_empty() {
                let count = buffer.len().min(self.pending.len());
                buffer[..count].copy_from_slice(&self.pending[..count]);
                self.pending = if count == self.pending.len() {
                    Bytes::new()
                } else {
                    self.pending.slice(count..)
                };
                return Poll::Ready(Ok(count));
            }
            if self.sequence.ended(Sender::Agent) {
                if let Some(error) = self.watch_end(cx) {
                    return Poll::Ready(Err(error));
                }
                return Poll::Ready(Ok(0));
            }
            if self.start < self.filled {
                let mut input = &self.scratch[self.start..self.filled];
                let result = self
                    .decoder
                    .next(&mut input, &mut self.sequence, Sender::Agent)
                    .map_err(classify)?;
                self.start = self.filled - input.len();
                match result {
                    Some(Frame::Data(bytes)) => {
                        self.pending = bytes;
                        continue;
                    }
                    Some(Frame::SendEnd) => {
                        if let Some(error) = self.watch_end(cx) {
                            return Poll::Ready(Err(error));
                        }
                        return Poll::Ready(Ok(0));
                    }
                    Some(_) => return Poll::Ready(Err(AttachmentError::InvalidFrame)),
                    None => {}
                }
            }
            let mut input = ReadBuf::new(&mut self.scratch);
            match Pin::new(self.io.as_mut().unwrap()).poll_read(cx, &mut input) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return Poll::Ready(Err(AttachmentError::AttachmentLost)),
                Poll::Ready(Ok(())) => {
                    self.start = 0;
                    self.filled = input.filled().len();
                    if self.filled == 0 {
                        return Poll::Ready(Err(AttachmentError::AttachmentLost));
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn begin(&mut self, frame: Frame) -> std::result::Result<(), AttachmentError> {
        let encoded = frame.encode().map_err(classify)?;
        self.sequence
            .accept(Sender::Daemon, &frame)
            .map_err(classify)?;
        self.output = Some(Output {
            header: encoded.header,
            written: 0,
            remaining: encoded.payload.len(),
            end: matches!(frame, Frame::SendEnd),
        });
        Ok(())
    }
    fn header(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), AttachmentError>> {
        let output = self.output.as_mut().ok_or(AttachmentError::InternalError)?;
        // At most five writes even with a one-byte-at-a-time socket adapter.
        while output.written < 5 {
            match Pin::new(self.io.as_mut().unwrap())
                .poll_write(cx, &output.header[output.written..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(count)) if count > 0 && count <= 5 - output.written => {
                    output.written += count
                }
                _ => return Poll::Ready(Err(AttachmentError::AttachmentLost)),
            }
        }
        Poll::Ready(Ok(()))
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        self.check()?;
        if let Some(error) = self.watch_end(cx) {
            return Poll::Ready(Err(error));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.output.is_none() {
            self.begin(Frame::Data(Bytes::copy_from_slice(
                &bytes[..bytes.len().min(self.max_data)],
            )))?;
        }
        if self.output.as_ref().unwrap().end {
            return Poll::Ready(Err(AttachmentError::InvalidFrame));
        }
        std::task::ready!(self.header(cx))?;
        let remaining = self.output.as_ref().unwrap().remaining;
        let length = bytes.len().min(remaining);
        match Pin::new(self.io.as_mut().unwrap()).poll_write(cx, &bytes[..length]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(count)) if count > 0 && count <= length => {
                let output = self.output.as_mut().unwrap();
                output.remaining -= count;
                if output.remaining == 0 {
                    self.output = None;
                }
                Poll::Ready(Ok(count))
            }
            _ => Poll::Ready(Err(AttachmentError::AttachmentLost)),
        }
    }
    fn end(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), AttachmentError>> {
        self.check()?;
        if let Some(error) = self.watch_end(cx) {
            return Poll::Ready(Err(error));
        }
        if self.output.is_none() {
            self.begin(Frame::SendEnd)?;
        }
        if !self.output.as_ref().unwrap().end {
            return Poll::Ready(Err(AttachmentError::InvalidFrame));
        }
        std::task::ready!(self.header(cx))?;
        self.output = None;
        Poll::Ready(Ok(()))
    }
}
fn classify(error: aap_types::Error) -> AttachmentError {
    if error.code == ErrorCode::LimitExceeded {
        AttachmentError::LimitExceeded
    } else {
        AttachmentError::InvalidFrame
    }
}

#[cfg(test)]
mod tests;
