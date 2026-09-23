//! Local stream wire adapter; authorization remains with the session service.
mod framed;
pub(crate) mod opening;

use aap_types::{
    ErrorCode, Result,
    stream::{
        self, Frame, Sender, Sequence,
        service::{AttachmentError, Connection, PendingStream},
    },
};
use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::Instant,
};

/// Drive one already admitted and upgraded local attachment. The caller must
/// validate the complete HTTP opening and finish 101 before invoking this.
/// This does not authenticate a listener, admit a resource, or retry a request.
pub async fn serve_upgraded<T>(
    mut io: T,
    request: stream::Open,
    pending: Box<dyn PendingStream>,
) -> Result<stream::Terminal>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    request.validate()?;
    let abort = pending.abort_handle();
    let mut connecting = pending.connect();
    // One byte suffices to reject every forbidden pre-OPENED input. Approval
    // allocates no application queue. The engine owns its shorter phase timers.
    let connection = tokio::time::timeout(Duration::from_secs(310), async {
        tokio::select! {
            biased;
            reason = poll_fn(|cx| forbidden(&mut io, cx)) => {
                abort.abort(reason);
                tokio::time::timeout(Duration::from_secs(2), &mut connecting)
                    .await.map_err(|_| ErrorCode::ResultUnavailable)?
            },
            result = &mut connecting => result,
        }
    })
    .await
    .map_err(|_| ErrorCode::ResultUnavailable)??;
    let connected = match connection {
        Connection::Terminal(terminal) => {
            let frame = Frame::Terminal(terminal.clone());
            Sequence::new(request)?.accept(Sender::Daemon, &frame)?;
            let encoded = frame.encode()?;
            tokio::time::timeout(Duration::from_secs(2), async {
                io.write_all(&encoded.header).await?;
                io.write_all(&encoded.payload).await?;
                io.flush().await
            })
            .await
            .map_err(|_| ErrorCode::ResultUnavailable)?
            .map_err(|_| ErrorCode::ResultUnavailable)?;
            return Ok(terminal);
        }
        Connection::Opened(connected) => connected,
    };
    let opened = connected.opened()?;
    let now = Instant::now();
    let lifetime = now + Duration::from_millis(opened.remaining_lifetime_ms);
    let opening_deadline = lifetime.min(now + Duration::from_millis(opened.idle_timeout_ms));
    let opening = Frame::Opened(opened.clone());
    Sequence::new(request.clone())?.accept(Sender::Daemon, &opening)?;
    let encoded = opening.encode()?;
    let opening_result = tokio::select! {
        biased;
        _ = abort.terminated() => return Err(ErrorCode::ResultUnavailable.into()),
        result = tokio::time::timeout_at(opening_deadline, write_opened(&mut io, &encoded)) => result,
    };
    match opening_result {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => {
            abort.abort(reason);
            return Err(ErrorCode::ResultUnavailable.into());
        }
        Err(_) => return Err(ErrorCode::ResultUnavailable.into()),
    }
    let (control, attachment) = framed::channel(Box::new(io), request, opened)?;
    let abort = connected.abort_handle();
    let mut relay = connected.relay(attachment);
    let terminal = tokio::time::timeout_at(
        lifetime + Duration::from_secs(2),
        poll_fn(|cx| {
            if let Some(reason) = control.fault(cx) {
                abort.abort(reason);
            }
            let result = relay.as_mut().poll(cx);
            if result.is_pending()
                && let Some(reason) = control.fault(cx)
            {
                // A read may have accepted SEND_END in this poll. Arm its separate
                // attachment monitor now, even if no application read remains.
                abort.abort(reason);
                return relay.as_mut().poll(cx);
            }
            result
        }),
    )
    .await
    .map_err(|_| ErrorCode::ResultUnavailable)??;
    control.finish(&terminal).await?;
    Ok(terminal)
}

fn forbidden<T: AsyncRead + Unpin>(io: &mut T, cx: &mut Context<'_>) -> Poll<AttachmentError> {
    let mut byte = [0];
    let mut buffer = ReadBuf::new(&mut byte);
    match Pin::new(io).poll_read(cx, &mut buffer) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) if !buffer.filled().is_empty() => {
            Poll::Ready(AttachmentError::InvalidFrame)
        }
        _ => Poll::Ready(AttachmentError::AttachmentLost),
    }
}

async fn write_opened<T: AsyncRead + AsyncWrite + Unpin>(
    io: &mut T,
    encoded: &stream::Encoded,
) -> std::result::Result<(), AttachmentError> {
    let mut offset = 0;
    poll_fn(|cx| {
        if let Poll::Ready(reason) = forbidden(io, cx) {
            return Poll::Ready(Err(reason));
        }
        for _ in 0..4 {
            let bytes = if offset < 5 {
                &encoded.header[offset..]
            } else {
                &encoded.payload[offset - 5..]
            };
            if bytes.is_empty() {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut *io).poll_write(cx, bytes) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(count)) if count > 0 && count <= bytes.len() => offset += count,
                _ => return Poll::Ready(Err(AttachmentError::AttachmentLost)),
            }
            if offset == 5 + encoded.payload.len() {
                return Poll::Ready(Ok(()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}
