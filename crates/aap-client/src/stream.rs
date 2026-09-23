//! Owned credential-free attachment. No upstream connector or custody code.
pub(crate) mod opening;
mod relay;
#[cfg(test)]
mod tests;

use aap_types::{
    BoxFuture, ErrorCode, Result,
    stream::{
        self, Decoder, Frame, Sender, Sequence,
        service::{
            Admission, ApplicationIo, AttachmentError, ConnectedStream, Connection, PendingStream,
            StreamAbort,
        },
    },
};
use bytes::Bytes;
use std::{
    future::poll_fn,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::Instant,
};

trait WireIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> WireIo for T {}

struct Reader {
    io: Box<dyn WireIo>,
    input: Bytes,
    decoder: Decoder,
    scratch: Box<[u8]>,
}
impl Reader {
    fn next(&mut self, sequence: &mut Sequence, cx: &mut Context<'_>) -> Poll<Result<Frame>> {
        for _ in 0..4 {
            if !self.input.is_empty() {
                let mut input = self.input.as_ref();
                let value = self
                    .decoder
                    .next(&mut input, sequence, Sender::Daemon)
                    .map_err(|_| ErrorCode::ResultUnavailable)?;
                self.input = if input.is_empty() {
                    Bytes::new()
                } else {
                    self.input.slice(self.input.len() - input.len()..)
                };
                if let Some(frame) = value {
                    return Poll::Ready(Ok(frame));
                }
            }
            let mut read = ReadBuf::new(&mut self.scratch);
            match Pin::new(&mut self.io).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) if !read.filled().is_empty() => {
                    self.input = Bytes::copy_from_slice(read.filled())
                }
                _ => return Poll::Ready(Err(ErrorCode::ResultUnavailable.into())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

struct State {
    reader: Reader,
    sequence: Sequence,
    opened: Option<stream::Opened>,
    lifetime: Instant,
    idle: Instant,
    relay: Option<relay::Relay>,
}
impl State {
    fn deadline(&self) -> Instant {
        self.relay
            .as_ref()
            .map_or(self.lifetime.min(self.idle), |relay| {
                relay.deadline(self.lifetime, self.idle)
            })
    }
    fn connect(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<stream::Terminal>>> {
        for _ in 0..4 {
            match std::task::ready!(self.reader.next(&mut self.sequence, cx))? {
                Frame::Pending(_) => {}
                Frame::Opened(opened) => {
                    let now = Instant::now();
                    self.lifetime = now + Duration::from_millis(opened.remaining_lifetime_ms);
                    self.idle = now + Duration::from_millis(opened.idle_timeout_ms);
                    self.opened = Some(opened);
                    return Poll::Ready(Ok(None));
                }
                Frame::Terminal(value) if self.reader.input.is_empty() => {
                    return Poll::Ready(Ok(Some(value)));
                }
                _ => return Poll::Ready(Err(ErrorCode::ResultUnavailable.into())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
struct Slot {
    state: Option<State>,
    failure: ErrorCode,
    waiter: Option<Waker>,
}
struct Shared {
    slot: Mutex<Slot>,
    changed: Arc<Notify>,
    ended: Notify,
}
impl Shared {
    fn stop(&self, failure: ErrorCode) {
        let (state, waiter) = {
            let mut slot = self
                .slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.state.is_none() {
                return;
            }
            slot.failure = failure;
            (slot.state.take(), slot.waiter.take())
        };
        drop(state);
        self.ended.notify_waiters();
        self.changed.notify_one();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
    fn poll<T>(
        &self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&mut State, &mut Context<'_>) -> Poll<Result<T>>,
    ) -> Poll<Result<T>> {
        let result = {
            let mut slot = match self.slot.lock() {
                Ok(slot) => slot,
                Err(_) => return Poll::Ready(Err(ErrorCode::InternalError.into())),
            };
            let failure = slot.failure;
            let Some(state) = &mut slot.state else {
                return Poll::Ready(Err(failure.into()));
            };
            let result = if Instant::now() >= state.deadline() {
                Poll::Ready(Err(ErrorCode::ResultUnavailable.into()))
            } else {
                let deadline = state.deadline();
                let result = operation(state, cx);
                // Ready I/O never wins an already expired phase deadline.
                if Instant::now() >= deadline {
                    Poll::Ready(Err(ErrorCode::ResultUnavailable.into()))
                } else {
                    result
                }
            };
            // Only an unresolved poll owns a wakeup. A retained control handle
            // must not keep a completed caller task alive through its waker.
            slot.waiter = if result.is_pending() {
                Some(cx.waker().clone())
            } else {
                None
            };
            result
        };
        self.changed.notify_one();
        if let Poll::Ready(Err(error)) = &result {
            self.stop(error.code);
        }
        result
    }
}
impl StreamAbort for Shared {
    fn abort(&self, _reason: AttachmentError) {
        self.stop(ErrorCode::ResultUnavailable);
    }
    fn terminated(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let notified = self.ended.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .state
                .is_none()
            {
                return;
            }
            notified.await;
        })
    }
}

struct Owner {
    request_id: String,
    shared: Arc<Shared>,
    watch: tokio::task::JoinHandle<()>,
}
impl Owner {
    fn new(io: Box<dyn WireIo>, request: stream::Open, input: Bytes) -> Result<Self> {
        let request_id = request.request_id.clone();
        let deadline = Instant::now() + Duration::from_secs(310);
        let shared = Arc::new(Shared {
            slot: Mutex::new(Slot {
                state: Some(State {
                    reader: Reader {
                        io,
                        input,
                        decoder: Decoder::default(),
                        scratch: vec![0; 1024].into_boxed_slice(),
                    },
                    sequence: Sequence::new(request)?,
                    opened: None,
                    lifetime: deadline,
                    idle: deadline,
                    relay: None,
                }),
                failure: ErrorCode::ResultUnavailable,
                waiter: None,
            }),
            changed: Arc::new(Notify::new()),
            ended: Notify::new(),
        });
        let watch = tokio::spawn(watch(Arc::downgrade(&shared), shared.changed.clone()));
        Ok(Self {
            request_id,
            shared,
            watch,
        })
    }
    async fn connect(self) -> Result<Connection> {
        match poll_fn(|cx| self.shared.poll(cx, State::connect))
            .await
            .map_err(|error| error.for_request(&self.request_id))?
        {
            Some(terminal) => Ok(Connection::Terminal(terminal)),
            None => Ok(Connection::Opened(Box::new(Connected(self)))),
        }
    }
    fn opened(&self) -> Result<stream::Opened> {
        let slot = self
            .shared
            .slot
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        let state = slot.state.as_ref().ok_or(slot.failure)?;
        let now = Instant::now();
        if now >= state.deadline() {
            return Err(ErrorCode::ResultUnavailable.into());
        }
        let mut opened = state.opened.clone().ok_or(ErrorCode::ResultUnavailable)?;
        opened.remaining_lifetime_ms =
            state.lifetime.saturating_duration_since(now).as_millis() as u64;
        if opened.remaining_lifetime_ms == 0 {
            return Err(ErrorCode::ResultUnavailable.into());
        }
        Ok(opened)
    }
    fn attach(&self, application: Box<dyn ApplicationIo>) -> Result<()> {
        let mut slot = self
            .shared
            .slot
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        let failure = slot.failure;
        let state = slot.state.as_mut().ok_or(failure)?;
        if Instant::now() >= state.deadline() || state.relay.is_some() {
            return Err(ErrorCode::ResultUnavailable.into());
        }
        state.relay = Some(relay::Relay::new(
            application,
            state.opened.as_ref().ok_or(ErrorCode::ResultUnavailable)?,
        ));
        Ok(())
    }
    async fn relay(self) -> Result<stream::Terminal> {
        poll_fn(|cx| self.shared.poll(cx, State::relay))
            .await
            .map_err(|error| error.for_request(&self.request_id))
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.shared.stop(ErrorCode::ResultUnavailable);
        self.watch.abort();
    }
}
async fn watch(weak: Weak<Shared>, changed: Arc<Notify>) {
    loop {
        let notified = changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let Some(shared) = weak.upgrade() else {
            return;
        };
        let deadline = {
            let slot = shared
                .slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(state) = &slot.state else {
                return;
            };
            state.deadline()
        };
        if Instant::now() >= deadline {
            shared.stop(ErrorCode::ResultUnavailable);
            return;
        }
        drop(shared);
        tokio::select! { _=tokio::time::sleep_until(deadline)=>{}, _=notified=>{} }
    }
}
struct Pending(Owner);
impl PendingStream for Pending {
    fn abort_handle(&self) -> Arc<dyn StreamAbort> {
        self.0.shared.clone()
    }
    fn connect(self: Box<Self>) -> BoxFuture<'static, Result<Connection>> {
        Box::pin(self.0.connect())
    }
}
struct Connected(Owner);
impl ConnectedStream for Connected {
    fn abort_handle(&self) -> Arc<dyn StreamAbort> {
        self.0.shared.clone()
    }
    fn opened(&self) -> Result<stream::Opened> {
        self.0
            .opened()
            .map_err(|error| error.for_request(&self.0.request_id))
    }
    fn relay(
        self: Box<Self>,
        application: Box<dyn ApplicationIo>,
    ) -> BoxFuture<'static, Result<stream::Terminal>> {
        let attached = self.0.attach(application);
        Box::pin(async move {
            attached.map_err(|error| error.for_request(&self.0.request_id))?;
            self.0.relay().await
        })
    }
}
