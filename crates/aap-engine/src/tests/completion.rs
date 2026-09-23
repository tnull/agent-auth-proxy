use super::dispatch::EndAuthority;
use super::*;

/// Stop at the last completion check, retire authority, then allow the current
/// poll to continue. Cleanup may be waiting for the completion's state locks.
pub(super) async fn retire_at_completion<T: Send + 'static>(
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
            .completion_hook
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
    let operation = session.operation(&id).unwrap();
    let held = session.clone();
    let closer = std::thread::spawn(move || match end {
        EndAuthority::Broker => broker.close(),
        EndAuthority::Session => broker.revoke(&held),
    });
    tokio::time::timeout(Duration::from_secs(2), session.core.cancelled.cancelled())
        .await
        .expect("retirement could not proceed during completion preparation");
    resume.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), task).await;
    closer.join().unwrap().unwrap();
    (
        result.expect("late completion did not finish").unwrap(),
        operation.status().unwrap(),
    )
}

pub(super) fn incomplete_endings(fixture: &Fixture, id: &str) {
    let batch = fixture.recorder.read(None, 256).unwrap();
    assert!(
        batch.gap.is_none(),
        "rejected completion lost observation identities"
    );
    for view in [aap_observe::View::Agent, aap_observe::View::Upstream] {
        let endings: Vec<_> = batch
            .records
            .iter()
            .filter_map(|record| {
                if record.event.request_id.as_deref() == Some(id)
                    && record.event.view == view
                    && let aap_observe::Data::FlowClose { complete, .. } = record.event.data
                {
                    return Some(complete);
                }
                None
            })
            .collect();
        assert_eq!(
            endings,
            [false],
            "retired work published a successful or duplicate ending"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completion_gate_rejects_provider_success_after_closure() {
    for end in [EndAuthority::Broker, EndAuthority::Session] {
        let fixture = Fixture::new().await;
        let broker = Arc::new(Broker::new(fixture.configuration()).unwrap());
        let session = broker.create_session(options()).unwrap();
        session
            .execute(fixture.request())
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        let input = fixture.request();
        let id = input.request_id.clone();
        let response = session.execute(input).await.unwrap();
        let (result, status) = retire_at_completion(broker, &session, end, async move {
            response.into_body().collect().await
        })
        .await;
        assert!(
            result.is_err(),
            "retired provider operation reported successful EOF"
        );
        assert_eq!(status.state, OperationState::OutcomeUnknown);
        incomplete_endings(&fixture, &id);
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    }
}
