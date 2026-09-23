use super::*;
use std::sync::{
    Weak,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{oneshot, watch};

pub(super) const BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct Progress {
    outcome: ReloadOutcome,
    complete: bool,
}
struct Reporter {
    output: watch::Sender<Progress>,
    host: Weak<Mutex<Generation>>,
    deadline: Instant,
}
impl Reporter {
    fn update(&self, update: impl FnOnce(&mut Progress)) {
        self.output.send_modify(|progress| {
            update(progress);
            if Instant::now() >= self.deadline {
                progress.outcome.retirement.cleanup_deadline_exceeded = true;
            }
        });
        // Do not hold the watch lock while acquiring the host lock. Read the
        // latest progress after acquisition, so racing updates cannot regress it.
        if let Some(host) = self.host.upgrade() {
            let mut host = host
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let progress = self.output.borrow().clone();
            if host.last_reload.as_ref().is_some_and(|previous| {
                previous.configuration_revision == progress.outcome.configuration_revision
            }) {
                host.last_reload = Some(progress.outcome);
            }
        }
    }
}

struct BlockingActivity(Arc<AtomicBool>);
impl Drop for BlockingActivity {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) struct Job {
    task: tokio::task::JoinHandle<()>,
    blocking_active: Arc<AtomicBool>,
    progress: watch::Receiver<Progress>,
    deadline: Instant,
}
impl Job {
    pub(super) fn start(
        host: Weak<Mutex<Generation>>,
        outcome: ReloadOutcome,
        deadline: Instant,
        broker: Arc<Broker>,
        sessions: HashMap<String, Attachment>,
        observers: HashMap<String, observation::Attachment>,
        #[cfg(test)] hook: Option<ReloadHook>,
    ) -> (Self, oneshot::Sender<()>) {
        let (output, progress) = watch::channel(Progress {
            outcome,
            complete: false,
        });
        let reporter = Reporter {
            output,
            host,
            deadline,
        };
        let blocking_active = Arc::new(AtomicBool::new(true));
        let activity = BlockingActivity(blocking_active.clone());
        let (start, ready) = oneshot::channel();
        let task = tokio::spawn(async move {
            if ready.await.is_err() {
                reporter.update(|progress| {
                    progress.outcome.retirement.authority_cleanup = AuthorityCleanup::Failed;
                    progress.complete = true;
                });
                return;
            }
            let cleanup = async {
                // The guard is owned by the actual blocking job, not its async
                // waiter. A cancelled wrapper cannot release blocking capacity.
                let result = tokio::task::spawn_blocking(move || {
                    let _activity = activity;
                    let failed = broker.close().is_err();
                    #[cfg(test)]
                    let failed = hook.is_some_and(|hook| hook().is_err()) || failed;
                    failed
                })
                .await;
                reporter.update(|progress| {
                    progress.outcome.retirement.authority_cleanup = match result {
                        Ok(false) => AuthorityCleanup::Complete,
                        _ => AuthorityCleanup::Failed,
                    };
                });
                for attachment in sessions.values() {
                    attachment.shutdown.cancel();
                }
                for attachment in observers.values() {
                    attachment.cancel_listener();
                }
                for (_, mut attachment) in sessions {
                    let failed = !matches!((&mut attachment.task).await, Ok(Ok(())));
                    drop(attachment);
                    reporter.update(|progress| {
                        progress.outcome.retirement.attachment_tasks_pending -= 1;
                        progress.outcome.retirement.attachment_cleanup_failed |= failed;
                    });
                }
                for (_, mut attachment) in observers {
                    let failed = attachment.join().await;
                    drop(attachment);
                    reporter.update(|progress| {
                        progress.outcome.retirement.attachment_tasks_pending -= 1;
                        progress.outcome.retirement.attachment_cleanup_failed |= failed;
                    });
                }
                reporter.update(|progress| {
                    progress.complete = true;
                });
            };
            tokio::pin!(cleanup);
            if tokio::time::timeout_at(deadline.into(), &mut cleanup)
                .await
                .is_err()
            {
                reporter.update(|progress| {
                    progress.outcome.retirement.cleanup_deadline_exceeded = true;
                });
                // Keep both ownership and the capacity reservation after timeout.
                cleanup.await;
            }
        });
        (
            Self {
                task,
                blocking_active,
                progress,
                deadline,
            },
            start,
        )
    }
    pub(super) fn is_active(&self) -> bool {
        let progress = self.progress.borrow();
        !self.task.is_finished()
            || self.blocking_active.load(Ordering::Acquire)
            || !progress.complete
            || progress.outcome.retirement.attachment_tasks_pending != 0
    }
    pub(super) fn outcome(&self) -> ReloadOutcome {
        let progress = self.progress.borrow().clone();
        let mut outcome = progress.outcome;
        if !progress.complete {
            outcome.retirement.cleanup_deadline_exceeded |= Instant::now() >= self.deadline;
            if self.task.is_finished() {
                outcome.retirement.authority_cleanup = AuthorityCleanup::Failed;
            }
        }
        outcome
    }
    pub(super) fn waiter(&self) -> Waiter {
        Waiter {
            progress: self.progress.clone(),
            deadline: self.deadline,
        }
    }
    pub(super) async fn join(self) -> ReloadOutcome {
        let mut outcome = self.outcome();
        if self.task.await.is_err() {
            outcome.retirement.authority_cleanup = AuthorityCleanup::Failed;
        }
        outcome
    }
}

pub(super) struct Waiter {
    progress: watch::Receiver<Progress>,
    deadline: Instant,
}
impl Waiter {
    pub(super) async fn wait(mut self, deadline: Instant) -> ReloadOutcome {
        let deadline = deadline.min(self.deadline);
        loop {
            let progress = self.progress.borrow_and_update().clone();
            if progress.complete || progress.outcome.retirement.cleanup_deadline_exceeded {
                return progress.outcome;
            }
            match tokio::time::timeout_at(deadline.into(), self.progress.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    let mut progress = self.progress.borrow().clone();
                    if !progress.complete {
                        progress.outcome.retirement.authority_cleanup = AuthorityCleanup::Failed;
                    }
                    return progress.outcome;
                }
                Err(_) => {
                    let mut progress = self.progress.borrow().clone();
                    progress.outcome.retirement.cleanup_deadline_exceeded = true;
                    return progress.outcome;
                }
            }
        }
    }
}
