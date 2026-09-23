use super::{Cancellation, http_drivers::HttpDrivers};
use std::future::Future;
use tokio::{sync::watch, time::Instant};

/// The response owns cancellation, while the transport owner retains joins.
pub(super) struct Driver {
    pub(super) stopped: Cancellation,
    progress: watch::Sender<Instant>,
    _owner: HttpDrivers,
}

impl Driver {
    pub(super) fn start(
        owner: HttpDrivers,
        connection: impl Future + Send + 'static,
        cancelled: Cancellation,
        deadline: Instant,
    ) -> Self {
        let stopped = Cancellation::default();
        let stop = stopped.clone();
        let (progress, mut changed) = watch::channel(deadline);
        owner.spawn(async move {
            let expiry = async {
                loop {
                    let deadline = *changed.borrow_and_update();
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(deadline) => return,
                        update = changed.changed() => if update.is_err() { return; },
                    }
                }
            };
            // Dropping the losing connection future closes its I/O even when
            // the caller never polls or drops the response body. Its JoinSet
            // owner confirms task termination independently of this token.
            tokio::select! {
                biased;
                _ = cancelled.cancelled() => stop.cancel(),
                _ = stop.cancelled() => {},
                _ = expiry => stop.cancel(),
                _ = connection => {},
            }
        });
        Self {
            stopped,
            progress,
            _owner: owner,
        }
    }

    pub(super) fn refresh(&self, deadline: Instant) {
        let now = Instant::now();
        let mut expired = false;
        self.progress.send_modify(|previous| {
            if now >= *previous {
                expired = true;
            } else {
                *previous = deadline;
            }
        });
        if expired {
            self.stopped.cancel();
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.stopped.cancel();
    }
}
