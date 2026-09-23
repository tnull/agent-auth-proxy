mod support;
use aap_observe::{ContentClass, Scope, SubscriptionLimits, View};
use aap_secrets::Availability;
use aap_types::{AgentService, ErrorCode, OperationState};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Limited};
use reuse_adapters::ObservationForwarder;
use std::{sync::atomic::Ordering, time::Duration};
use support::{Fixture, bounded};

async fn consume(response: aap_types::Response) {
    assert_eq!(response.status(), 200);
    let body = bounded(Limited::new(response.into_body(), 16 * 1024).collect())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(body, "data: [redacted]\n\n");
    support::safe(&body);
}

#[tokio::test]
async fn queued_approval_preserves_binding_and_keeps_secrets_unresolved() {
    let mut fixture = Fixture::new(true).await;
    let mut invalid = fixture.request();
    invalid.resource = "not-granted".into();
    assert!(
        matches!(fixture.session.execute(invalid).await, Err(error) if error.code == ErrorCode::PolicyDenied)
    );
    let mut invalid = fixture.request();
    invalid.target = "https://unenrolled.invalid/v1/chat/completions".into();
    assert!(
        matches!(fixture.session.execute(invalid).await, Err(error) if error.code == ErrorCode::PolicyDenied)
    );
    assert_eq!(fixture.store.reads.load(Ordering::SeqCst), 0);
    for allow in [true, false] {
        let request = fixture.request();
        let expected = request.clone();
        let before = fixture.store.resolved();
        let running = fixture.session.clone();
        let execution = tokio::spawn(async move { running.execute(request).await });
        let pending = bounded(fixture.pending.recv())
            .await
            .expect("approval was not queued");
        assert!(
            *pending.request().operation == expected,
            "approval changed the operation binding"
        );
        assert_eq!(pending.request().session_id, fixture.session.id());
        assert_eq!(pending.request().item_id, "account");
        assert!(pending.request().context_id.is_none());
        assert_eq!(
            bounded(fixture.session.request_status(expected.request_id.clone()))
                .await
                .unwrap()
                .state,
            OperationState::PendingApproval
        );
        assert_eq!(fixture.store.resolved(), before);
        pending.decide(allow).unwrap();
        let result = bounded(execution).await.unwrap();
        if allow {
            consume(result.unwrap()).await;
        } else {
            assert!(matches!(result, Err(error) if error.code == ErrorCode::PolicyDenied));
        }
    }
    assert_eq!(fixture.store.resolved(), 1);
    assert_eq!(fixture.receipts(), 1);
}

#[tokio::test]
async fn cancellation_and_changed_custody_cannot_release_a_stale_secret() {
    for change in [
        "cancel",
        "revoke",
        "rotate",
        "lock",
        "unavailable",
        "interaction",
        "delete",
        "drop-approver",
        "drop-execution",
    ] {
        let mut fixture = Fixture::new(true).await;
        let request = fixture.request();
        let id = request.request_id.clone();
        let running = fixture.session.clone();
        let execution = tokio::spawn(async move { running.execute(request).await });
        let pending = bounded(fixture.pending.recv())
            .await
            .expect("approval was not queued");
        let previous_lease = pending.request().credential_lease.clone();
        if change == "drop-execution" {
            execution.abort();
            assert!(matches!(bounded(execution).await, Err(error) if error.is_cancelled()));
            assert!(pending.decide(true).is_err());
            assert_eq!(
                fixture.session.request_status(id).await.unwrap().state,
                OperationState::Cancelled
            );
            assert_eq!(fixture.store.resolved(), 0);
            assert_eq!(fixture.receipts(), 0);
            continue;
        }
        let expected = match change {
            "cancel" => {
                assert_eq!(
                    fixture.session.cancel(id).await.unwrap().state,
                    OperationState::Cancelled
                );
                ErrorCode::RequestConflict
            }
            "revoke" => {
                fixture.broker.revoke(&fixture.session).unwrap();
                ErrorCode::SessionInvalid
            }
            "rotate" => {
                fixture.store.rotate();
                ErrorCode::VaultUnavailable
            }
            "lock" => {
                fixture.store.availability(Availability::Locked);
                ErrorCode::VaultLocked
            }
            "unavailable" => {
                fixture.store.availability(Availability::Unavailable);
                ErrorCode::VaultUnavailable
            }
            "interaction" => {
                fixture
                    .store
                    .availability(Availability::InteractionRequired);
                ErrorCode::InteractionUnavailable
            }
            "delete" => {
                fixture.store.delete();
                ErrorCode::PolicyDenied
            }
            "drop-approver" => ErrorCode::InteractionUnavailable,
            _ => unreachable!(),
        };
        if matches!(change, "cancel" | "revoke") {
            let result = bounded(execution).await.unwrap();
            assert!(matches!(result, Err(error) if error.code == expected));
            assert!(
                pending.decide(true).is_err(),
                "late decision retained a live receiver"
            );
        } else {
            if change == "drop-approver" {
                drop(pending);
            } else {
                pending.decide(true).unwrap();
            }
            assert!(
                matches!(bounded(execution).await.unwrap(), Err(error) if error.code == expected)
            );
        }
        assert_eq!(fixture.store.resolved(), 0);
        assert_eq!(fixture.receipts(), 0);
        if matches!(change, "rotate" | "lock" | "unavailable") {
            if change != "rotate" {
                fixture.store.availability(Availability::Ready);
            }
            let request = fixture.request();
            let running = fixture.session.clone();
            let execution = tokio::spawn(async move { running.execute(request).await });
            let pending = bounded(fixture.pending.recv()).await.unwrap();
            assert_ne!(pending.request().credential_lease, previous_lease);
            pending.decide(true).unwrap();
            consume(bounded(execution).await.unwrap().unwrap()).await;
            assert_eq!(fixture.store.resolved(), 1);
            assert_eq!(fixture.receipts(), 1);
        }
    }
}

#[tokio::test]
async fn observation_delivery_requires_consumer_ack_and_preserves_failed_pages() {
    let fixture = Fixture::new(false).await;
    let subscription = fixture
        .recorder
        .subscribe(
            Scope {
                sessions: vec![fixture.session.id().into()],
                views: vec![View::Agent, View::Upstream],
                classes: vec![ContentClass::Metadata, ContentClass::Content],
            },
            SubscriptionLimits {
                max_events: 512,
                max_bytes: 512 * 1024,
            },
        )
        .unwrap();
    consume(fixture.session.execute(fixture.request()).await.unwrap()).await;
    let mut forwarder = ObservationForwarder::new(subscription);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let retained = sender.clone();
    let delivery = tokio::spawn(async move {
        let result = forwarder.forward(&sender).await;
        (forwarder, result)
    });
    let page = bounded(receiver.recv())
        .await
        .expect("no observation page delivered");
    assert!(!page.batch.deliveries.is_empty());
    assert!(page.batch.gap.is_none());
    support::safe(&serde_json::to_vec(&page.batch).unwrap());
    for delivery in &page.batch.deliveries {
        if let aap_observe::Data::ContentChunk { body_base64, .. } = &delivery.record.event.data {
            support::safe(&STANDARD.decode(body_base64).unwrap());
        }
    }
    assert!(
        !delivery.is_finished(),
        "queue acceptance was mistaken for consumer acknowledgment"
    );
    drop(page);
    let (mut forwarder, failed) = bounded(delivery).await.unwrap();
    assert!(matches!(failed, Err(error) if error.code == ErrorCode::ObservationUnavailable));
    // A dropped page is delivered again, not silently acknowledged.
    let delivery = tokio::spawn(async move {
        let result = forwarder.forward(&retained).await;
        (forwarder, result)
    });
    let retry = bounded(receiver.recv()).await.unwrap();
    assert_eq!(retry.batch.deliveries[0].delivery_id, 1);
    retry.acknowledge().unwrap();
    let (mut forwarder, result) = bounded(delivery).await.unwrap();
    assert!(result.unwrap() > 0);
    drop(receiver);
    // Consumer disconnect is not itself failure of local recording acceptance.
    consume(fixture.session.execute(fixture.request()).await.unwrap()).await;
    let (closed, receiver) = tokio::sync::mpsc::channel(1);
    drop(receiver);
    assert!(
        matches!(forwarder.forward(&closed).await, Err(error) if error.code == ErrorCode::ObservationUnavailable)
    );
    let before = fixture.store.resolved();
    fixture.recorder.set_available(false);
    assert!(
        matches!(fixture.session.execute(fixture.request()).await, Err(error) if error.code == ErrorCode::ObservationUnavailable)
    );
    assert_eq!(fixture.store.resolved(), before);
    assert_eq!(fixture.receipts(), 2);
}

#[tokio::test]
async fn a_full_or_closed_inbox_denies_and_observer_ack_cannot_approve() {
    let mut fixture = Fixture::new(true).await;
    let subscription = fixture
        .recorder
        .subscribe(
            Scope {
                sessions: vec![fixture.session.id().into()],
                views: vec![View::Agent, View::Upstream],
                classes: vec![ContentClass::Metadata, ContentClass::Content],
            },
            SubscriptionLimits {
                max_events: 512,
                max_bytes: 512 * 1024,
            },
        )
        .unwrap();
    let request = fixture.request();
    let id = request.request_id.clone();
    let running = fixture.session.clone();
    let execution = tokio::spawn(async move { running.execute(request).await });
    bounded(async {
        while fixture.pending.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        matches!(bounded(fixture.session.execute(fixture.request())).await,
        Err(error) if error.code == ErrorCode::InteractionUnavailable)
    );
    let pending = fixture.pending.recv().await.unwrap();
    let mut forwarder = ObservationForwarder::new(subscription);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let delivery = tokio::spawn(async move { forwarder.forward(&sender).await });
    bounded(receiver.recv())
        .await
        .unwrap()
        .acknowledge()
        .unwrap();
    assert!(bounded(delivery).await.unwrap().unwrap() > 0);
    assert_eq!(
        fixture.session.request_status(id).await.unwrap().state,
        OperationState::PendingApproval
    );
    assert_eq!(fixture.store.resolved(), 0);
    assert_eq!(fixture.receipts(), 0);
    pending.decide(false).unwrap();
    assert!(
        matches!(bounded(execution).await.unwrap(), Err(error) if error.code == ErrorCode::PolicyDenied)
    );
    fixture.pending.close();
    assert!(
        matches!(bounded(fixture.session.execute(fixture.request())).await,
        Err(error) if error.code == ErrorCode::InteractionUnavailable)
    );
    assert_eq!(fixture.store.resolved(), 0);
    assert_eq!(fixture.receipts(), 0);
}

#[tokio::test]
async fn expired_waits_reject_late_approvals_and_observer_acknowledgments() {
    let mut fixture = Fixture::new(true).await;
    tokio::time::pause();
    let request = fixture.request();
    let running = fixture.session.clone();
    let execution = tokio::spawn(async move { running.execute(request).await });
    let pending = bounded(fixture.pending.recv()).await.unwrap();
    tokio::time::advance(Duration::from_secs(61)).await;
    assert!(
        matches!(bounded(execution).await.unwrap(), Err(error) if error.code == ErrorCode::InteractionUnavailable)
    );
    assert!(pending.decide(true).is_err());
    assert_eq!(fixture.store.resolved(), 0);
    assert_eq!(fixture.receipts(), 0);
    tokio::time::resume();

    let fixture = Fixture::new(false).await;
    let subscription = fixture
        .recorder
        .subscribe(
            Scope {
                sessions: vec![fixture.session.id().into()],
                views: vec![View::Agent],
                classes: vec![ContentClass::Metadata, ContentClass::Content],
            },
            SubscriptionLimits {
                max_events: 512,
                max_bytes: 512 * 1024,
            },
        )
        .unwrap();
    consume(fixture.session.execute(fixture.request()).await.unwrap()).await;
    tokio::time::pause();
    let mut forwarder = ObservationForwarder::new(subscription);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let retained = sender.clone();
    let delivery = tokio::spawn(async move {
        let result = forwarder.forward(&sender).await;
        (forwarder, result)
    });
    bounded(async {
        while receiver.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    tokio::time::advance(Duration::from_secs(11)).await;
    let (mut forwarder, result) = bounded(delivery).await.unwrap();
    assert!(matches!(result, Err(error) if error.code == ErrorCode::ObservationUnavailable));
    // The unacknowledged page still occupies the bounded destination queue.
    assert!(
        matches!(forwarder.forward(&retained).await, Err(error) if error.code == ErrorCode::LimitExceeded)
    );
    assert!(receiver.recv().await.unwrap().acknowledge().is_err());
    let delivery = tokio::spawn(async move {
        let result = forwarder.forward(&retained).await;
        (forwarder, result)
    });
    let retry = bounded(receiver.recv()).await.unwrap();
    assert_eq!(retry.batch.deliveries[0].delivery_id, 1);
    retry.acknowledge().unwrap();
    let (_, result) = bounded(delivery).await.unwrap();
    assert!(result.unwrap() > 0);
}

#[tokio::test]
async fn an_ack_ready_after_the_deadline_does_not_advance_the_cursor() {
    let fixture = Fixture::new(false).await;
    let subscription = fixture
        .recorder
        .subscribe(
            Scope {
                sessions: vec![fixture.session.id().into()],
                views: vec![View::Agent],
                classes: vec![ContentClass::Metadata],
            },
            SubscriptionLimits {
                max_events: 512,
                max_bytes: 512 * 1024,
            },
        )
        .unwrap();
    consume(fixture.session.execute(fixture.request()).await.unwrap()).await;
    let mut forwarder = ObservationForwarder::new(subscription);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    tokio::time::pause();
    let mut forward = Box::pin(forwarder.forward(&sender));
    std::future::poll_fn(|context| {
        assert!(std::future::Future::poll(forward.as_mut(), context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let page = receiver.try_recv().unwrap();
    // Keep the forwarder unpolled until both its deadline and receipt are ready.
    tokio::time::advance(Duration::from_secs(11)).await;
    page.acknowledge().unwrap();
    assert!(matches!(forward.await, Err(error) if error.code == ErrorCode::ObservationUnavailable));
    let mut retry = Box::pin(forwarder.forward(&sender));
    std::future::poll_fn(|context| {
        assert!(std::future::Future::poll(retry.as_mut(), context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let page = receiver.try_recv().unwrap();
    assert_eq!(page.batch.deliveries[0].delivery_id, 1);
    page.acknowledge().unwrap();
    assert!(retry.await.unwrap() > 0);
}
