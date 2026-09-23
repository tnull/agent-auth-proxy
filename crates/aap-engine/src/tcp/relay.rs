use super::*;
use aap_transport::tcp::relay::{Duplex, Limits};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Engine-owned application forwarding. Completion includes final required
/// observation; abandoning this future terminates the retained operation.
#[must_use = "a relay forwards only while polled; dropping it closes the operation"]
pub struct TcpRelay {
    connected: ConnectedTcp,
}
pub(super) struct ActiveRelay {
    pub io: Duplex,
    pub observation: observation::Observation,
}
impl ConnectedTcp {
    /// Transfer a trusted application attachment into the operation immediately.
    /// The wire adapter must finish OPENED first and map explicit SEND_END to
    /// application EOF. Raw agent attachment EOF must be an error, not send-end.
    /// Dropping or cancelling the returned future closes both relay directions.
    pub fn relay(self, local: TcpSocket) -> TcpRelay {
        if self.opened().is_ok()
            && let Err(cause) = self.operation.start_relay(local, &self.timing)
        {
            self.operation.finish(cause);
        }
        TcpRelay { connected: self }
    }
}
impl Future for TcpRelay {
    type Output = stream::Terminal;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.connected.session.check().is_err() {
            self.connected.operation.finish(stream::Cause::SessionEnded);
        }
        self.connected.operation.poll_relay(cx)
    }
}

impl Operation {
    fn start_relay(
        &self,
        local: TcpSocket,
        timing: &ConnectionTiming,
    ) -> std::result::Result<(), stream::Cause> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| stream::Cause::InternalError)?;
        if terminal(state.status.state) || self.cancelled.is_cancelled() {
            return Err(stream::Cause::Cancelled);
        }
        if Instant::now() >= timing.idle {
            return Err(stream::Cause::Timeout);
        }
        if state.relay.is_some() || state.capacity.is_none() {
            return Err(stream::Cause::InternalError);
        }
        let upstream = state.socket.take().ok_or(stream::Cause::InternalError)?;
        let limits = self.profile.limits;
        state.relay = Some(ActiveRelay {
            io: Duplex::new(
                local,
                upstream,
                Limits {
                    // Leave room in the 128 KiB reservation for bounded framing
                    // buffers and redaction scratch, including retained fragments.
                    max_chunk: (limits.max_data_bytes as usize).min(16 * 1024),
                    send_limit: limits.send_limit,
                    receive_limit: limits.receive_limit,
                    idle_timeout: Duration::from_millis(limits.idle_timeout_ms),
                    idle_deadline: timing.idle,
                    lifetime: timing.lifetime,
                },
                self.cancelled.clone(),
            )
            .map_err(|_| stream::Cause::InternalError)?,
            observation: observation::Observation::new(self.flow.clone(), self.profile.inspection),
        });
        self.changed.notify_one();
        Ok(())
    }

    fn poll_relay(&self, cx: &mut Context<'_>) -> Poll<stream::Terminal> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poison) => {
                let mut state = poison.into_inner();
                self.finish_locked(&mut state, stream::Cause::InternalError);
                return Poll::Ready(Self::outcome_locked(&state));
            }
        };
        if terminal(state.status.state) {
            return Poll::Ready(Self::outcome_locked(&state));
        }
        let result = if let Some(relay) = &mut state.relay {
            let before = relay.io.deadline();
            let result = relay.io.poll(cx, &mut relay.observation);
            if before != relay.io.deadline() {
                self.changed.notify_one();
            }
            result
        } else {
            self.finish_locked(&mut state, stream::Cause::InternalError);
            return Poll::Ready(Self::outcome_locked(&state));
        };
        if let Poll::Ready(outcome) = result {
            let cause = if self.cancelled.is_cancelled() {
                stream::Cause::Cancelled
            } else {
                outcome.cause
            };
            self.finish_locked(&mut state, cause);
            Poll::Ready(Self::outcome_locked(&state))
        } else {
            Poll::Pending
        }
    }

    pub(super) async fn watch(&self, session_cancelled: Cancellation) {
        loop {
            let changed = self.changed.notified();
            let deadline = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if terminal(state.status.state) {
                    return;
                }
                let deadline = state.deadline();
                // Do not arm an already expired timer: Tokio rounds its wake
                // tick upward, while authority is measured by the exact instant.
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    self.finish_locked(&mut state, stream::Cause::Timeout);
                    return;
                }
                deadline
            };
            let Some(deadline) = deadline else {
                return;
            };
            tokio::select! {
                biased;
                _ = self.cancelled.cancelled() => return,
                _ = session_cancelled.cancelled() => { self.finish(stream::Cause::SessionEnded); return; },
                _ = changed => {},
                _ = tokio::time::sleep_until(deadline) => {
                    let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if terminal(state.status.state) { return; }
                    if state.deadline().is_some_and(|current| Instant::now() >= current) {
                        self.finish_locked(&mut state, stream::Cause::Timeout);
                        return;
                    }
                }
            }
        }
    }
}
