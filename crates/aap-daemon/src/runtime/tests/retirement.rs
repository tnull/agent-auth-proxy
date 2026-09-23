use super::*;

struct Release(Option<std::sync::mpsc::Sender<()>>);
impl Release {
    fn finish(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.finish();
    }
}
fn pause_cleanup(control: &Control) -> (tokio::sync::oneshot::Receiver<()>, Release) {
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    *control.cleanup_hook.lock().unwrap() = Some(Box::new(move || {
        entered.send(()).unwrap();
        let _ = released.recv();
        Ok(())
    }));
    (waiting, Release(Some(release)))
}
async fn completed(control: &Control) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if control
                .state
                .lock()
                .unwrap()
                .last_reload
                .as_ref()
                .is_some_and(|outcome| {
                    outcome.retirement.authority_cleanup == AuthorityCleanup::Complete
                        && outcome.retirement.attachment_tasks_pending == 0
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("host-owned cleanup did not finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retirement_keeps_unjoined_attachments_after_deadline_and_reports_failure() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Stopped(Arc<AtomicBool>);
    impl Drop for Stopped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    for fail in [false, true] {
        let fixture = Fixture::new().await;
        let attachment = fixture
            .control
            .create(CreateSession {
                resources: vec![],
                items: None,
                lifetime_seconds: 60,
                require_approval: false,
                require_observation: false,
            })
            .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let original = {
            let mut state = fixture.control.state.lock().unwrap();
            let attachment = state.sessions.get_mut(&attachment.session_id).unwrap();
            let cancellation = attachment.shutdown.clone();
            let stopped = Stopped(stopped.clone());
            std::mem::replace(
                &mut attachment.task,
                tokio::spawn(async move {
                    let _stopped = stopped;
                    cancellation.cancelled().await;
                    entered.send(()).unwrap();
                    let _ = released.await;
                    if fail {
                        Err(ErrorCode::InternalError.into())
                    } else {
                        Ok(())
                    }
                }),
            )
        };
        fixture.write(2, 2);
        let control = fixture.control.clone();
        let caller = tokio::spawn(async move { control.reload().await });
        waiting.await.unwrap();
        original.await.unwrap().unwrap();
        let report = tokio::time::timeout(Duration::from_millis(2500), caller)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            report.retirement.authority_cleanup,
            AuthorityCleanup::Complete
        );
        assert_eq!(report.retirement.attachment_tasks_pending, 1);
        assert!(report.retirement.cleanup_deadline_exceeded);
        assert!(!report.retirement.drain_confirmed);
        assert!(
            !stopped.load(Ordering::Acquire),
            "timeout aborted or forgot the owned attachment"
        );
        release.send(()).unwrap();
        completed(&fixture.control).await;
        assert!(stopped.load(Ordering::Acquire));
        let state = fixture.control.state.lock().unwrap();
        let outcome = state.last_reload.as_ref().unwrap();
        assert_eq!(outcome.retirement.attachment_cleanup_failed, fail);
        assert!(outcome.retirement.cleanup_deadline_exceeded);
        assert!(!outcome.retirement.drain_confirmed);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_wait_is_bounded_without_discarding_pending_cleanup() {
    let fixture = Fixture::new().await;
    fixture.write(2, 2);
    let (entered, mut release) = pause_cleanup(&fixture.control);
    let control = fixture.control.clone();
    let mut caller = tokio::spawn(async move { control.reload().await });
    entered.await.unwrap();
    let result = tokio::time::timeout(Duration::from_millis(2500), &mut caller).await;
    let report = match result {
        Ok(result) => Some(serde_json::to_value(result.unwrap().unwrap()).unwrap()),
        Err(_) => None,
    };
    release.finish();
    if report.is_none() {
        let _ = caller.await;
    }
    let report = report.expect("reload waited beyond its cleanup budget");
    assert_eq!(report["configuration_revision"], 2);
    assert_eq!(report["retirement"]["authority_cleanup"], "pending");
    assert_eq!(report["retirement"]["cleanup_deadline_exceeded"], true);
    assert_eq!(report["retirement"]["drain_confirmed"], false);
    completed(&fixture.control).await;
    let state = fixture.control.state.lock().unwrap();
    let latest = serde_json::to_value(state.last_reload.as_ref().unwrap()).unwrap();
    assert_eq!(
        latest["retirement"]["cleanup_deadline_exceeded"], true,
        "late completion erased the exceeded deadline"
    );
}

#[tokio::test]
async fn retirement_worker_panic_still_cancels_and_joins_attachments() {
    let fixture = Fixture::new().await;
    let old = fixture.broker();
    for _ in 0..2 {
        fixture
            .control
            .create(CreateSession {
                resources: vec![],
                items: None,
                lifetime_seconds: 60,
                require_approval: false,
                require_observation: false,
            })
            .unwrap();
    }
    fixture.write(2, 2);
    *fixture.control.cleanup_hook.lock().unwrap() =
        Some(Box::new(|| panic!("synthetic cleanup failure")));
    let report = fixture.control.reload().await.unwrap();
    assert_eq!(report.configuration_revision, 2);
    assert!(old.is_closed());
    assert_eq!(
        report.retirement.authority_cleanup,
        AuthorityCleanup::Failed
    );
    assert_eq!(report.retirement.attachment_tasks_pending, 0);
    assert!(!report.retirement.attachment_cleanup_failed);
    assert!(!report.retirement.drain_confirmed);
    discover(&fixture.broker().create_session(options()).unwrap())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_reload_caller_keeps_cleanup_owned_and_blocks_another_retirement() {
    let fixture = Fixture::new().await;
    fixture.write(2, 2);
    let (entered, mut release) = pause_cleanup(&fixture.control);
    let control = fixture.control.clone();
    let mut caller = tokio::spawn(async move { control.reload().await });
    entered.await.unwrap();
    caller.abort();
    let stopped = tokio::time::timeout(Duration::from_millis(250), &mut caller).await;
    let detached = matches!(&stopped, Ok(Err(error)) if error.is_cancelled());
    fixture.write(3, 3);
    let busy = fixture.control.reload().await;
    release.finish();
    if stopped.is_err() {
        let _ = caller.await;
    }
    assert!(
        detached,
        "the operator request could not detach from blocked cleanup"
    );
    assert!(
        matches!(busy, Err(error) if error.code == ErrorCode::LimitExceeded),
        "a second retirement escaped the host's cleanup capacity"
    );
    completed(&fixture.control).await;
    let next = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match fixture.control.reload().await {
                Err(error) if error.code == ErrorCode::LimitExceeded => {
                    tokio::task::yield_now().await
                }
                result => break result,
            }
        }
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        serde_json::to_value(next).unwrap()["configuration_revision"],
        3
    );
    assert_eq!(
        fixture.control.store.status().await.unwrap().availability,
        aap_secrets::Availability::Ready
    );
}
