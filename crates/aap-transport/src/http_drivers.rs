//! Ownership and joins for established upstream HTTP connection drivers.

use std::{
    future::{Future, poll_fn},
    sync::{Arc, Mutex, MutexGuard},
    task::Poll,
};
use tokio::{task::JoinSet, time::Instant};

#[derive(Clone, Default)]
pub struct HttpDrivers(Arc<Owner>);

#[derive(Default)]
struct Owner {
    state: Mutex<State>,
    joiner: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct State {
    tasks: JoinSet<()>,
    failed: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HttpDriverStatus {
    /// Drivers not yet joined, including any completed but unreaped tasks.
    pub tasks_pending: usize,
    /// A driver panicked, was aborted, or tracking state was poisoned.
    pub join_failed: bool,
}

impl HttpDrivers {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|error| {
            let mut state = error.into_inner();
            state.failed = true;
            state
        })
    }

    pub(super) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        // Reap completed work on every admission, even without a host waiter.
        self.status();
        self.state().tasks.spawn(future);
    }

    /// Snapshot established driver ownership, not whole-transport quiescence.
    /// DNS/connect/handshake futures and caller-held body buffers are excluded.
    pub fn status(&self) -> HttpDriverStatus {
        let joiner = self.0.joiner.try_lock();
        let mut state = self.state();
        if joiner.is_ok() {
            while let Some(result) = state.tasks.try_join_next() {
                state.failed |= result.is_err();
            }
        }
        HttpDriverStatus {
            tasks_pending: state.tasks.len(),
            join_failed: state.failed,
        }
    }

    /// Join owned drivers until idle or the absolute deadline. Does not cancel
    /// operations or close admission; the host must do that independently.
    /// Timeout or dropping this waiter never removes unfinished tasks. Concurrent
    /// waiters share one join owner and each retains its original deadline.
    pub async fn wait_until_idle(&self, deadline: Instant) -> HttpDriverStatus {
        let wait = async {
            let _joiner = self.0.joiner.lock().await;
            poll_fn(|context| {
                let mut state = self.state();
                loop {
                    match state.tasks.poll_join_next(context) {
                        Poll::Ready(Some(result)) => state.failed |= result.is_err(),
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            })
            .await;
        };
        let _ = tokio::time::timeout_at(deadline, wait).await;
        self.status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancelled_and_concurrent_waiters_do_not_lose_owned_tasks() {
        let drivers = HttpDrivers::default();
        let (finish, finished) = tokio::sync::oneshot::channel();
        drivers.spawn(async {
            let _ = finished.await;
        });
        let waiting = drivers.clone();
        let caller = tokio::spawn(async move {
            waiting
                .wait_until_idle(Instant::now() + Duration::from_secs(2))
                .await
        });
        while drivers.0.joiner.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
        let report = drivers
            .wait_until_idle(Instant::now() + Duration::from_millis(10))
            .await;
        assert_eq!(report.tasks_pending, 1);
        assert!(!report.join_failed);
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(drivers.status().tasks_pending, 1);
        finish.send(()).unwrap();
        let report = drivers
            .wait_until_idle(Instant::now() + Duration::from_secs(2))
            .await;
        assert_eq!(report.tasks_pending, 0);
        assert!(!report.join_failed);
    }

    #[tokio::test]
    async fn failed_join_is_sticky_and_does_not_forget_other_tasks() {
        let drivers = HttpDrivers::default();
        let (finish, finished) = tokio::sync::oneshot::channel();
        drivers.spawn(async {
            panic!("synthetic driver failure");
        });
        drivers.spawn(async {
            let _ = finished.await;
        });
        let report = drivers
            .wait_until_idle(Instant::now() + Duration::from_millis(10))
            .await;
        assert_eq!(report.tasks_pending, 1);
        assert!(report.join_failed);
        finish.send(()).unwrap();
        let report = drivers
            .wait_until_idle(Instant::now() + Duration::from_secs(2))
            .await;
        assert_eq!(report.tasks_pending, 0);
        assert!(report.join_failed);
        drivers.spawn(async {});
        assert!(
            drivers
                .wait_until_idle(Instant::now() + Duration::from_secs(2))
                .await
                .join_failed
        );
    }
}
