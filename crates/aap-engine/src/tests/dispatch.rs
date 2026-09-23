//! Deterministic final-admission races, including a stalled revocation walk.
use super::*;

pub(super) struct CountedTransport {
    inner: Arc<dyn Transport>,
    calls: Arc<AtomicUsize>,
}
impl CountedTransport {
    pub(super) fn install(configuration: &mut Configuration) -> Arc<AtomicUsize> {
        let calls = Arc::new(AtomicUsize::new(0));
        configuration.transport = Arc::new(Self {
            inner: configuration.transport.clone(),
            calls: calls.clone(),
        });
        calls
    }
}
impl Transport for CountedTransport {
    fn execute(
        &self,
        endpoint: aap_transport::Endpoint,
        request: http::Request<Bytes>,
        limits: aap_transport::Limits,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<Response>> {
        // Count the handoff itself, even if cancellation wins before the real
        // TLS transport's future can send bytes to the independent origin.
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.execute(endpoint, request, limits, cancellation)
    }
}

#[derive(Clone, Copy)]
pub(super) enum EndAuthority {
    Broker,
    Session,
}
enum Tracked {
    Http(Arc<Operation>),
    Tcp(Arc<crate::tcp::Operation>),
}
impl Tracked {
    fn status(&self) -> OperationStatus {
        match self {
            Self::Http(operation) => operation.status().unwrap(),
            Self::Tcp(operation) => operation.status().unwrap(),
        }
    }
}

/// Pause after all preparation checks but before final dispatch. Revoke the
/// authority while preventing its operation walk from cancelling this item.
/// The final gate, not an earlier check or that walk, must stop the handoff.
pub(super) async fn close_at_ready<T: Send + 'static>(
    broker: Arc<Broker>,
    session: &Session,
    end: EndAuthority,
    work: impl Future<Output = T> + Send + 'static,
) -> (T, OperationStatus) {
    let (reached, reached_rx) = tokio::sync::oneshot::channel();
    let (resume, resume_rx) = std::sync::mpsc::channel();
    assert!(
        broker
            .host
            .dispatch_hook
            .lock()
            .unwrap()
            .replace(Box::new(move |id| {
                reached.send(id.to_owned()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            }))
            .is_none()
    );
    let task = tokio::spawn(work);
    let id = tokio::time::timeout(Duration::from_secs(2), reached_rx)
        .await
        .expect("operation did not reach final dispatch")
        .unwrap();
    let tracked = {
        let operations = session.core.operations.lock().unwrap();
        if let Some(operation) = operations.items.get(&id) {
            Tracked::Http(operation.clone())
        } else {
            Tracked::Tcp(operations.streams[&id].clone())
        }
    };
    let (locked, locked_rx) = tokio::sync::oneshot::channel();
    let (unlock, unlock_rx) = std::sync::mpsc::channel();
    let held = session.clone();
    let locker = std::thread::spawn(move || {
        let _operations = held.core.operations.lock().unwrap();
        locked.send(()).unwrap();
        // A failed test also releases this lock by dropping its sender.
        let _ = unlock_rx.recv_timeout(Duration::from_secs(5));
    });
    tokio::time::timeout(Duration::from_secs(2), locked_rx)
        .await
        .unwrap()
        .unwrap();
    let closing = broker.clone();
    let revoked = session.clone();
    let closer = std::thread::spawn(move || match end {
        EndAuthority::Broker => closing.close(),
        EndAuthority::Session => closing.revoke(&revoked),
    });
    tokio::time::timeout(Duration::from_secs(2), session.core.cancelled.cancelled())
        .await
        .expect("authority was not revoked before operation cleanup");
    assert_eq!(broker.is_closed(), matches!(end, EndAuthority::Broker));
    assert_eq!(tracked.status().state, OperationState::Ready);
    resume.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), task).await;
    // Finish both native threads before asserting the operation result.
    unlock.send(()).unwrap();
    locker.join().unwrap();
    closer.join().unwrap().unwrap();
    let result = result.expect("dispatch did not terminate").unwrap();
    (result, tracked.status())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_dispatch_gate_blocks_closed_provider_handoff() {
    provider_boundary(EndAuthority::Broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_dispatch_gate_blocks_revoked_provider_handoff() {
    provider_boundary(EndAuthority::Session).await;
}

async fn provider_boundary(end: EndAuthority) {
    let fixture = Fixture::new().await;
    let mut configuration = fixture.configuration();
    let calls = CountedTransport::install(&mut configuration);
    let broker = Arc::new(Broker::new(configuration).unwrap());
    let session = broker.create_session(options()).unwrap();
    let positive = fixture.request();
    let completed_id = positive.request_id.clone();
    session
        .execute(positive)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let completed = session.operation(&completed_id).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    let input = fixture.request();
    let running = session.clone();
    let (result, status) = close_at_ready(broker.clone(), &session, end, async move {
        running.execute(input).await
    })
    .await;
    assert!(result.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "revoked authority handed a prepared provider request to the transport"
    );
    assert_eq!(status.state, OperationState::Cancelled);
    assert_eq!(completed.status().unwrap().state, OperationState::Completed);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
    if matches!(end, EndAuthority::Session) {
        let survivor = broker.create_session(options()).unwrap();
        survivor
            .execute(fixture.request())
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn final_dispatch_gate_keeps_dispatched_provider_outcome_uncertain() {
    let mut fixture = Fixture::new().await;
    let mut reply = Reply::body("data: pending\n\n");
    reply
        .headers
        .push(("content-type".into(), "text/event-stream".into()));
    reply.delay = Duration::from_secs(5);
    fixture.origin = Origin::spawn(reply).await;
    let mut configuration = fixture.configuration();
    let calls = CountedTransport::install(&mut configuration);
    let broker = Broker::new(configuration).unwrap();
    let session = broker.create_session(options()).unwrap();
    let input = fixture.request();
    let id = input.request_id.clone();
    let response = session.execute(input).await.unwrap();
    let operation = session.operation(&id).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    broker.close().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), response.into_body().collect())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(
        operation.status().unwrap().state,
        OperationState::OutcomeUnknown
    );
    assert!(session.execute(fixture.request()).await.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "closure retried dispatched work"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
}
