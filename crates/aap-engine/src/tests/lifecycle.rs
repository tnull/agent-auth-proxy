use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CloseAt {
    Revalidate,
    Resolve,
}

/// Return a successful native result in the same poll that closes authority.
/// This deliberately does not yield after closure: the caller must recheck it.
pub(super) struct ClosingStore {
    inner: Arc<dyn SecretStore>,
    armed: Mutex<Option<(Weak<Broker>, CloseAt)>>,
}
impl ClosingStore {
    pub(super) fn install(configuration: &mut Configuration) -> Arc<Self> {
        let store = Arc::new(Self {
            inner: configuration.stores["default"].clone(),
            armed: Mutex::new(None),
        });
        configuration.stores.insert("default".into(), store.clone());
        store
    }
    pub(super) fn arm(&self, broker: &Arc<Broker>, phase: CloseAt) {
        assert!(
            self.armed
                .lock()
                .unwrap()
                .replace((Arc::downgrade(broker), phase))
                .is_none()
        );
    }
    fn returned(&self, phase: CloseAt) {
        let close = {
            let mut armed = self.armed.lock().unwrap();
            if armed
                .as_ref()
                .is_some_and(|(_, selected)| *selected == phase)
            {
                armed.take()
            } else {
                None
            }
        };
        if let Some((broker, _)) = close {
            broker.upgrade().unwrap().close().unwrap();
        }
    }
}
impl SecretStore for ClosingStore {
    fn status(&self) -> BoxFuture<'_, aap_secrets::Result<aap_secrets::StoreStatus>> {
        self.inner.status()
    }
    fn metadata<'a>(
        &'a self,
        item: &'a ItemRef,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::ItemMetadata>> {
        self.inner.metadata(item)
    }
    fn revalidate<'a>(
        &'a self,
        item: &'a ItemRef,
        lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<()>> {
        Box::pin(async move {
            self.inner.revalidate(item, lease).await?;
            self.returned(CloseAt::Revalidate);
            Ok(())
        })
    }
    fn resolve<'a>(
        &'a self,
        item: &'a ItemRef,
        lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::Snapshot>> {
        Box::pin(async move {
            let snapshot = self.inner.resolve(item, lease).await?;
            self.returned(CloseAt::Resolve);
            Ok(snapshot)
        })
    }
}

pub(super) fn no_authentication_prepared(fixture: &Fixture, request_id: &str) {
    let records = fixture.recorder.read(None, 256).unwrap();
    assert!(records.gap.is_none());
    assert!(
        !records.records.iter().any(|record| {
            (record.event.request_id.as_deref() == Some(request_id)
                || record.event.parent_request_id.as_deref() == Some(request_id))
                && matches!(
                    record.event.data,
                    aap_observe::Data::AuthTransition { inserted: true, .. }
                )
        }),
        "credentials were prepared after their broker closed"
    );
}

#[tokio::test]
async fn broker_close_during_revalidation_prevents_a_new_secret_lookup() {
    late_provider_result(CloseAt::Revalidate).await;
}

#[tokio::test]
async fn broker_close_during_resolution_discards_the_returned_provider_key() {
    late_provider_result(CloseAt::Resolve).await;
}

async fn late_provider_result(phase: CloseAt) {
    let fixture = Fixture::new().await;
    let mut configuration = fixture.configuration();
    let store = ClosingStore::install(&mut configuration);
    let broker = Arc::new(Broker::new(configuration).unwrap());
    let session = broker.create_session(options()).unwrap();
    session
        .execute(fixture.request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
    store.arm(&broker, phase);
    let request = fixture.request();
    let id = request.request_id.clone();
    invalid(session.execute(request).await);
    assert!(broker.is_closed());
    assert_eq!(
        fixture.resolutions.load(Ordering::SeqCst),
        if phase == CloseAt::Resolve { 2 } else { 1 },
        "closure allowed a new secret lookup after revalidation"
    );
    no_authentication_prepared(&fixture, &id);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
}

fn invalid<T>(result: Result<T>) {
    assert!(
        matches!(result, Err(error) if error.code == ErrorCode::SessionInvalid),
        "closed broker admitted a session operation"
    );
}

async fn rejects_every_entry(session: &Session, fixture: &Fixture) {
    let request = fixture.request();
    invalid(session.execute(request.clone()).await);
    invalid(
        session
            .forward(aap_types::proxy::ForwardRequest {
                request_id: request.request_id.clone(),
                auth_context: None,
                method: request.method,
                target: request.target,
                headers: request.headers,
                body_base64: request.body_base64,
            })
            .await,
    );
    invalid(
        session
            .search_items(SearchItems {
                uri: fixture.origin.origin(),
                query: None,
                cursor: None,
            })
            .await,
    );
    invalid(
        session
            .get_login(GetLogin {
                request_id: aap_types::ids::random_id(16).unwrap(),
                item_id: "provider-key".into(),
                uri: fixture.origin.origin(),
            })
            .await,
    );
    let context = AuthContext {
        auth_context: aap_types::ids::random_id(32).unwrap(),
    };
    invalid(session.auth_status(context.clone()).await);
    invalid(session.logout(context).await);
    invalid(session.request_status(request.request_id.clone()).await);
    invalid(session.cancel(request.request_id.clone()).await);
    invalid(
        session
            .open_stream(stream::Open {
                request_id: request.request_id,
                resource: "provider".into(),
            })
            .await,
    );
    invalid(
        session
            .admit_connect(format!("fixture.test:{}", fixture.origin.address.port()))
            .await,
    );
}

#[tokio::test]
async fn broker_close_revokes_all_clones_without_locking_a_shared_store() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let other = Broker::new(fixture.configuration()).unwrap();
    let first = broker.create_session(options()).unwrap();
    let second = broker.create_session(options()).unwrap();
    let independent = other.create_session(options()).unwrap();
    assert!(!broker.is_closed());
    let completed = fixture.request();
    for session in [&first, &second, &independent] {
        session
            .execute(completed.clone())
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    let retained = first.operation(&completed.request_id).unwrap();
    assert_eq!(retained.status().unwrap().state, OperationState::Completed);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 3);
    let clones = [first.clone(), second.clone()];
    broker.close().unwrap();
    assert!(broker.is_closed(), "broker admission stayed open");
    broker.close().unwrap();
    invalid(broker.create_session(options()));
    for session in [&first, &second, &clones[0], &clones[1]] {
        rejects_every_entry(session, &fixture).await;
    }
    assert_eq!(retained.status().unwrap().state, OperationState::Completed);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    assert!(!other.is_closed());
    independent
        .execute(fixture.request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 4);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 4);
    other.close().unwrap();
}

#[tokio::test]
async fn broker_close_orders_concurrent_creation_and_repeated_closers() {
    let fixture = Fixture::new().await;
    for _ in 0..16 {
        let broker = Broker::new(fixture.configuration()).unwrap();
        let seed = broker.create_session(options()).unwrap();
        let barrier = std::sync::Barrier::new(11);
        let admitted = std::thread::scope(|scope| {
            let creators: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        broker.create_session(options())
                    })
                })
                .collect();
            let closers: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        broker.close().unwrap();
                    })
                })
                .collect();
            let sessions: Vec<_> = creators
                .into_iter()
                .filter_map(|thread| match thread.join().unwrap() {
                    Ok(session) => Some(session),
                    Err(error) => {
                        assert_eq!(error.code, ErrorCode::SessionInvalid);
                        None
                    }
                })
                .collect();
            for thread in closers {
                thread.join().unwrap();
            }
            sessions
        });
        assert!(broker.is_closed(), "concurrent closers left admission open");
        invalid(broker.create_session(options()));
        for session in admitted.iter().chain(std::iter::once(&seed)) {
            invalid(session.execute(fixture.request()).await);
            assert!(session.core.cancelled.is_cancelled());
        }
    }
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn broker_close_cancels_pending_approval_before_a_late_decision() {
    let fixture = Fixture::new().await;
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
    let (decision, decision_rx) = tokio::sync::oneshot::channel();
    let mut configuration = fixture.configuration();
    configuration.require_approval = true;
    configuration.approval = Some(Arc::new(Gate {
        received: sent,
        decision: Mutex::new(Some(decision_rx)),
    }));
    let broker = Broker::new(configuration).unwrap();
    let session = broker.create_session(options()).unwrap();
    let request = fixture.request();
    let request_id = request.request_id.clone();
    let running = session.clone();
    let execution = tokio::spawn(async move { running.execute(request).await });
    let approval = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(approval.operation.request_id, request_id);
    let operation = session.operation(&request_id).unwrap();
    assert_eq!(
        operation.status().unwrap().state,
        OperationState::PendingApproval
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    broker.close().unwrap();
    assert_eq!(
        operation.status().unwrap().state,
        OperationState::Cancelled,
        "closure did not cancel the pending operation"
    );
    invalid(
        tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(decision.send(true).is_err());
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    invalid(session.request_status(request_id).await);
}

#[tokio::test]
async fn broker_close_stops_polled_response_delivery_without_claiming_rollback() {
    let mut fixture = Fixture::new().await;
    let mut reply = Reply::body("data: delayed\n\n");
    reply
        .headers
        .push(("content-type".into(), "text/event-stream".into()));
    reply.delay = Duration::from_secs(5);
    fixture.origin = Origin::spawn(reply).await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    let request = fixture.request();
    let response = session.execute(request.clone()).await.unwrap();
    let operation = session.operation(&request.request_id).unwrap();
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    broker.close().unwrap();
    assert_eq!(
        operation.status().unwrap().state,
        OperationState::OutcomeUnknown,
        "closure left dispatched work live"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), response.into_body().collect())
            .await
            .unwrap()
            .is_err()
    );
    invalid(session.execute(request).await);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn broker_close_terminates_unpolled_http_without_closing_a_shared_peer() {
    let mut fixture = Fixture::new().await;
    let mut reply = Reply::body("data: delayed\n\n");
    reply
        .headers
        .push(("content-type".into(), "text/event-stream".into()));
    reply.delay = Duration::from_secs(30);
    fixture.origin = Origin::spawn(reply).await;
    let shared = Arc::new(HttpsTransport::new([fixture.origin.certificate.clone()]).unwrap());
    let drivers = shared.http_drivers();
    let mut configuration = fixture.configuration();
    configuration.transport = shared.clone();
    let first = Broker::new(configuration).unwrap();
    let mut configuration = fixture.configuration();
    configuration.transport = shared;
    let second = Broker::new(configuration).unwrap();
    let session = first.create_session(options()).unwrap();
    let peer = second.create_session(options()).unwrap();
    let request = fixture.request();
    let held = session.execute(request.clone()).await.unwrap();
    let operation = session.operation(&request.request_id).unwrap();
    let independent = peer.execute(fixture.request()).await.unwrap();
    assert_eq!(fixture.origin.active_connections(), 2);
    first.close().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.origin.active_connections() != 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("broker closure left an unpolled upstream socket alive");
    assert_eq!(
        operation.status().unwrap().state,
        OperationState::OutcomeUnknown
    );
    assert!(!second.is_closed());
    assert_eq!(drivers.status().tasks_pending, 1);
    assert_eq!(
        fixture.store.status().await.unwrap().availability,
        aap_secrets::Availability::Ready
    );
    assert!(held.into_body().collect().await.is_err());
    second.close().unwrap();
    let joined = drivers
        .wait_until_idle(Instant::now() + Duration::from_secs(2))
        .await;
    assert_eq!(joined.tasks_pending, 0);
    assert!(!joined.join_failed);
    assert!(independent.into_body().collect().await.is_err());
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn broker_close_stays_closed_and_notifies_every_session_on_cleanup_failure() {
    let fixture = Fixture::new().await;
    for poison_registry in [true, false] {
        let broker = Broker::new(fixture.configuration()).unwrap();
        let damaged = broker.create_session(options()).unwrap();
        let healthy = broker.create_session(options()).unwrap();
        std::thread::scope(|scope| {
            let result = scope
                .spawn(|| {
                    if poison_registry {
                        let _guard = broker.host.sessions.lock().unwrap();
                        panic!("synthetic registry failure");
                    } else {
                        let _guard = damaged.core.operations.lock().unwrap();
                        panic!("synthetic operation failure");
                    }
                })
                .join();
            assert!(result.is_err());
        });
        for _ in 0..2 {
            assert!(
                matches!(broker.close(), Err(error) if error.code == ErrorCode::InternalError),
                "cleanup failure was reported as success"
            );
            assert!(broker.is_closed());
            invalid(broker.create_session(options()));
            for session in [&damaged, &healthy] {
                assert!(session.core.cancelled.is_cancelled());
                invalid(session.execute(fixture.request()).await);
            }
        }
    }
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn admission_closure_defers_callbacks_until_host_publication_is_released() {
    use std::task::{Context, Wake, Waker};

    struct Probe {
        broker: Weak<Broker>,
        published: Arc<Mutex<bool>>,
        wakes: AtomicUsize,
        safe: AtomicBool,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let broker = self.broker.upgrade().unwrap();
            let safe = broker.is_closed()
                && broker.host.sessions.try_lock().is_ok()
                && self.published.try_lock().is_ok_and(|state| *state);
            self.safe.store(safe, Ordering::SeqCst);
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    let fixture = Fixture::new().await;
    let broker = Arc::new(Broker::new(fixture.configuration()).unwrap());
    let other = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    session
        .execute(fixture.request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let published = Arc::new(Mutex::new(false));
    let probe = Arc::new(Probe {
        broker: Arc::downgrade(&broker),
        published: published.clone(),
        wakes: AtomicUsize::new(0),
        safe: AtomicBool::new(false),
    });
    let waker = Waker::from(probe.clone());
    let mut waiting = std::pin::pin!(session.core.cancelled.cancelled());
    assert!(
        waiting
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    {
        let mut state = published.lock().unwrap();
        broker.close_admission();
        broker.close_admission();
        assert!(broker.is_closed());
        assert_eq!(
            probe.wakes.load(Ordering::SeqCst),
            0,
            "admission closure ran a cancellation callback"
        );
        assert!(!session.core.cancelled.is_cancelled());
        invalid(broker.create_session(options()));
        *state = true;
    }
    // Retained authority is already unusable, even before notification/cleanup.
    rejects_every_entry(&session, &fixture).await;
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    broker.close().unwrap();
    assert!(session.core.cancelled.is_cancelled());
    assert_eq!(probe.wakes.load(Ordering::SeqCst), 1);
    assert!(probe.safe.load(Ordering::SeqCst));
    let independent = other.create_session(options()).unwrap();
    independent
        .execute(fixture.request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
}
