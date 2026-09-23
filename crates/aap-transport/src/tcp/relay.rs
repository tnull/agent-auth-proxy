//! Bounded admitted duplex I/O. The engine supplies authority and observation.

use super::TcpSocket;
use crate::Cancellation;
use aap_types::{
    ErrorCode, Result,
    stream::{self, Cause},
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

pub struct Limits {
    pub max_chunk: usize,
    pub send_limit: u64,
    pub receive_limit: u64,
    pub idle_timeout: Duration,
    pub idle_deadline: Instant,
    pub lifetime: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub cause: Cause,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}

/// Trusted synchronous admission, not an export sink for unredacted bytes.
/// Implementations must accept required safe observation before returning Ok.
pub trait Gate {
    fn before_forward(
        &mut self,
        direction: Direction,
        bytes: &[u8],
    ) -> std::result::Result<(), Cause>;
    fn before_end(&mut self, direction: Direction) -> std::result::Result<(), Cause>;
}

/// Owns two application I/O endpoints and at most 32 KiB of payload per
/// direction. The engine reserves aggregate capacity before constructing it.
/// No task is spawned; an owner must poll or explicitly terminate retained work.
pub struct Duplex {
    sockets: Option<[TcpSocket; 2]>,
    directions: [CopyState; 2],
    limits: Limits,
    cancellation: Cancellation,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    timer: Pin<Box<Sleep>>,
    outcome: Option<Outcome>,
    first: usize,
}

struct CopyState {
    buffer: Box<[u8]>,
    filled: usize,
    written: usize,
    admitted: u64,
    forwarded: u64,
    read_end: bool,
    write_end: bool,
    stalled: Option<Instant>,
}
impl CopyState {
    fn new(bytes: usize) -> Self {
        Self {
            buffer: vec![0; bytes].into_boxed_slice(),
            filled: 0,
            written: 0,
            admitted: 0,
            forwarded: 0,
            read_end: false,
            write_end: false,
            stalled: None,
        }
    }
}

impl Duplex {
    /// Requires the host's existing Tokio runtime. Already expired limits are
    /// accepted structurally, but the first poll terminates before any I/O.
    /// I/O adapters must report actual accepted payload prefixes, not enqueue
    /// success into an additional unaccounted buffer.
    pub fn new(
        local: TcpSocket,
        upstream: TcpSocket,
        limits: Limits,
        cancellation: Cancellation,
    ) -> Result<Self> {
        let now = Instant::now();
        if limits.max_chunk == 0
            || limits.max_chunk > stream::MAX_DATA_BYTES
            || limits.send_limit == 0
            || limits.send_limit > stream::MAX_DIRECTION_BYTES
            || limits.receive_limit == 0
            || limits.receive_limit > stream::MAX_DIRECTION_BYTES
            || limits.idle_timeout.is_zero()
            || limits.idle_timeout > Duration::from_millis(stream::MAX_IDLE_MS)
            || limits.idle_deadline.saturating_duration_since(now) > limits.idle_timeout
            || limits.lifetime.saturating_duration_since(now)
                > Duration::from_millis(stream::MAX_LIFETIME_MS)
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let waiting = cancellation.clone();
        Ok(Self {
            sockets: Some([local, upstream]),
            directions: [
                CopyState::new(limits.max_chunk),
                CopyState::new(limits.max_chunk),
            ],
            timer: Box::pin(tokio::time::sleep_until(
                limits.idle_deadline.min(limits.lifetime),
            )),
            limits,
            cancellation,
            cancelled: Box::pin(async move { waiting.cancelled().await }),
            outcome: None,
            first: 0,
        })
    }

    /// Poll bounded work without spawning a driver. Each I/O endpoint denotes
    /// an application stream: a framed local adapter must map explicit SEND_END
    /// to EOF and unexpected attachment EOF to an error. Frame/control limits
    /// and final control delivery remain with that adapter and its engine owner.
    pub fn poll(&mut self, cx: &mut Context<'_>, gate: &mut dyn Gate) -> Poll<Outcome> {
        if let Some(outcome) = self.outcome {
            return Poll::Ready(outcome);
        }
        // Subscribe even if no socket becomes ready, so cancellation wakes us.
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return self.finish(Cause::Cancelled);
        }
        if let Err(cause) = self.check() {
            return self.finish(cause);
        }
        // A permanently ready peer cannot monopolize the runtime. Alternate
        // directions and bound both callbacks and socket polls per invocation.
        self.first = 1 - self.first;
        for _ in 0..8 {
            let mut progress = false;
            for offset in 0..2 {
                match self.step((self.first + offset) % 2, cx, gate) {
                    Ok(value) => progress |= value,
                    Err(cause) => return self.finish(cause),
                }
            }
            if self.directions.iter().all(|state| state.write_end) {
                return self.finish(Cause::OrderlyEnd);
            }
            if !progress {
                let deadline = self.deadline();
                self.timer.as_mut().reset(deadline);
                if self.timer.as_mut().poll(cx).is_ready() {
                    return self.finish(Cause::Timeout);
                }
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Close retained I/O immediately without polling it or flushing pending
    /// payload. This preserves actual partial-write counts and a prior terminal
    /// result. Only the relay's own two-ended path can establish orderly end.
    pub fn terminate(&mut self, cause: Cause) -> Outcome {
        self.close(gate_cause(cause))
    }

    fn deadline(&self) -> Instant {
        self.directions
            .iter()
            .filter_map(|state| state.stalled)
            .fold(
                self.limits.lifetime.min(self.limits.idle_deadline),
                Instant::min,
            )
    }

    fn check(&self) -> std::result::Result<(), Cause> {
        if self.cancellation.is_cancelled() {
            return Err(Cause::Cancelled);
        }
        if Instant::now() >= self.deadline() {
            return Err(Cause::Timeout);
        }
        Ok(())
    }

    fn step(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
        gate: &mut dyn Gate,
    ) -> std::result::Result<bool, Cause> {
        self.check()?;
        if self.directions[index].write_end {
            return Ok(false);
        }
        let direction = if index == 0 {
            Direction::Outbound
        } else {
            Direction::Inbound
        };
        if self.directions[index].written < self.directions[index].filled {
            let state = &self.directions[index];
            let result = Pin::new(&mut self.sockets.as_mut().unwrap()[1 - index])
                .poll_write(cx, &state.buffer[state.written..state.filled]);
            match result {
                Poll::Pending => Ok(false),
                Poll::Ready(Err(_)) | Poll::Ready(Ok(0)) => Err(io_cause(1 - index)),
                Poll::Ready(Ok(count)) => {
                    let state = &mut self.directions[index];
                    if count > state.filled - state.written {
                        return Err(Cause::InternalError);
                    }
                    // Accepted bytes count even if cancellation/expiry became
                    // visible inside the I/O implementation's ready result.
                    state.written += count;
                    state.forwarded += count as u64;
                    self.check()?;
                    let now = Instant::now();
                    self.limits.idle_deadline = now + self.limits.idle_timeout;
                    let state = &mut self.directions[index];
                    if state.written == state.filled {
                        state.written = 0;
                        state.filled = 0;
                        state.stalled = None;
                    } else {
                        state.stalled = Some(now + self.limits.idle_timeout);
                    }
                    Ok(true)
                }
            }
        } else if self.directions[index].read_end {
            match Pin::new(&mut self.sockets.as_mut().unwrap()[1 - index]).poll_shutdown(cx) {
                Poll::Pending => Ok(false),
                Poll::Ready(Err(_)) => Err(io_cause(1 - index)),
                Poll::Ready(Ok(())) => {
                    self.check()?;
                    self.directions[index].write_end = true;
                    self.directions[index].stalled = None;
                    Ok(true)
                }
            }
        } else {
            let limit = if index == 0 {
                self.limits.send_limit
            } else {
                self.limits.receive_limit
            };
            let state = &mut self.directions[index];
            let remaining = limit - state.admitted;
            // Once the limit is reached, a one-byte probe distinguishes a
            // permitted orderly EOF from excess data. It is never forwarded.
            let room = self.limits.max_chunk.min(remaining.max(1) as usize);
            let mut bytes = ReadBuf::new(&mut state.buffer[..room]);
            match Pin::new(&mut self.sockets.as_mut().unwrap()[index]).poll_read(cx, &mut bytes) {
                Poll::Pending => Ok(false),
                Poll::Ready(Err(_)) => Err(io_cause(index)),
                Poll::Ready(Ok(())) => {
                    let count = bytes.filled().len();
                    self.check()?;
                    if count == 0 {
                        gate.before_end(direction).map_err(gate_cause)?;
                        self.check()?;
                        let state = &mut self.directions[index];
                        state.read_end = true;
                        state.stalled = Some(Instant::now() + self.limits.idle_timeout);
                    } else {
                        if count as u64 > remaining {
                            return Err(Cause::LimitExceeded);
                        }
                        let state = &mut self.directions[index];
                        state.filled = count;
                        state.admitted += count as u64;
                        state.stalled = Some(Instant::now() + self.limits.idle_timeout);
                        gate.before_forward(direction, &state.buffer[..count])
                            .map_err(gate_cause)?;
                        self.check()?;
                    }
                    Ok(true)
                }
            }
        }
    }

    fn finish(&mut self, cause: Cause) -> Poll<Outcome> {
        Poll::Ready(self.close(cause))
    }

    fn close(&mut self, cause: Cause) -> Outcome {
        if let Some(outcome) = self.outcome {
            return outcome;
        }
        let outcome = Outcome {
            cause,
            sent_bytes: self.directions[0].forwarded,
            received_bytes: self.directions[1].forwarded,
        };
        self.outcome = Some(outcome);
        self.sockets.take();
        for state in &mut self.directions {
            state.buffer = Box::new([]);
            state.filled = 0;
            state.written = 0;
            state.stalled = None;
        }
        outcome
    }
}

fn io_cause(index: usize) -> Cause {
    if index == 0 {
        Cause::AttachmentLost
    } else {
        Cause::UpstreamUnavailable
    }
}
fn gate_cause(cause: Cause) -> Cause {
    // A failed gate cannot manufacture orderly completion.
    if cause == Cause::OrderlyEnd {
        Cause::InternalError
    } else {
        cause
    }
}

#[cfg(test)]
mod tests;
