use super::{dispatch::EndAuthority, *};

enum Tracked {
    Request(Arc<Operation>),
    Issuance(Arc<crate::vault::Issuance>),
}
impl Tracked {
    fn status(&self) -> OperationStatus {
        match self {
            Self::Request(operation) => operation.status().unwrap(),
            Self::Issuance(operation) => operation.status().unwrap(),
        }
    }
}

pub(super) async fn retire_at_publication<T: Send + 'static>(
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
            .publication_hook
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
        .unwrap()
        .unwrap();
    let tracked = {
        let operations = session.core.operations.lock().unwrap();
        if let Some(operation) = operations.items.get(&id) {
            Tracked::Request(operation.clone())
        } else {
            Tracked::Issuance(operations.issuances[&id].clone())
        }
    };
    let held = session.clone();
    let closer = std::thread::spawn(move || match end {
        EndAuthority::Broker => broker.close(),
        EndAuthority::Session => broker.revoke(&held),
    });
    tokio::time::timeout(Duration::from_secs(2), session.core.cancelled.cancelled())
        .await
        .expect("publication preparation prevented authority retirement");
    resume.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), task).await;
    closer.join().unwrap().unwrap();
    (
        result.expect("publication did not finish").unwrap(),
        tracked.status(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_gate_rejects_retired_placeholder_issuance() {
    use super::vault::{issuance, website_configuration};
    use aap_types::profile::LoginEncoding;
    for end in [EndAuthority::Broker, EndAuthority::Session] {
        let fixture = Fixture::new().await;
        let broker = Arc::new(
            Broker::new(website_configuration(&fixture, LoginEncoding::Form).await).unwrap(),
        );
        let session = broker.create_session(options()).unwrap();
        let positive = issuance(&fixture);
        let positive_id = positive.request_id.clone();
        session.get_login(positive).await.unwrap();
        let completed = session.issuance(&positive_id).unwrap().unwrap();
        assert_eq!(broker.host.contexts.available_permits(), 63);
        let input = issuance(&fixture);
        let running = session.clone();
        let (result, status) = retire_at_publication(broker.clone(), &session, end, async move {
            running.get_login(input).await
        })
        .await;
        assert!(result.is_err());
        assert_eq!(
            status.state,
            OperationState::Cancelled,
            "retired issuance was reported completed"
        );
        assert_eq!(completed.status().unwrap().state, OperationState::Completed);
        assert_eq!(
            session.core.vault.lock().unwrap().contexts.len(),
            1,
            "late placeholder binding entered the catalog"
        );
        assert_eq!(
            broker.host.contexts.available_permits(),
            63,
            "rejected publication retained context capacity"
        );
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        assert!(fixture.origin.requests.lock().unwrap().is_empty());
    }
}
