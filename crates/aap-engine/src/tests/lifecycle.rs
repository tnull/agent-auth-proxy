use super::*;

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
