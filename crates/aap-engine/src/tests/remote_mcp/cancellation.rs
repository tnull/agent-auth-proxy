use super::*;

fn notification(id: Value) -> Value {
    json!({"jsonrpc":"2.0","method":"notifications/cancelled",
        "params":{"requestId":id,"reason":"untrusted cancellation reason"}})
}
async fn empty_accepted(response: Response) {
    assert_eq!(response.status(), 202);
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
}

async fn slow_fixture() -> (Fixture, Arc<tokio::sync::Notify>) {
    slow_fixture_with_ack(202).await
}

async fn slow_fixture_with_ack(ack_status: u16) -> (Fixture, Arc<tokio::sync::Notify>) {
    let mut fixture = Fixture::new().await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let received = entered.clone();
    let mapped = Mutex::new(None::<Value>);
    fixture.origin = Origin::with_handler(move |request| {
        assert_eq!(request.headers["authorization"], "Bearer synthetic-api-key");
        let message: Value = serde_json::from_slice(&request.body).unwrap();
        let mut reply = match message["method"].as_str().unwrap() {
            "initialize" => {
                let mut reply = Reply::body(
                    json!({"jsonrpc":"2.0","id":message["id"],
                    "result":{"protocolVersion":VERSION,"capabilities":{"tools":{}},
                    "serverInfo":{"name":"fixture","version":"1"}}})
                    .to_string(),
                );
                reply.headers.push((
                    "mcp-session-id".into(),
                    "private-remote-session-cancel".into(),
                ));
                reply
            }
            "notifications/initialized" => {
                let mut reply = Reply::body("");
                reply.status = 202;
                reply
            }
            "tools/call" => {
                *mapped.lock().unwrap() = Some(message["id"].clone());
                received.notify_one();
                let mut reply = Reply::body(
                    json!({"jsonrpc":"2.0","id":message["id"],
                    "result":{"content":[{"type":"text","text":"completed remotely"}]}})
                    .to_string(),
                );
                reply.delay = Duration::from_secs(30);
                reply
            }
            "notifications/cancelled" => {
                assert_eq!(
                    message["params"],
                    json!({"requestId":mapped.lock().unwrap().as_ref().unwrap()})
                );
                assert_eq!(
                    request.headers["mcp-session-id"],
                    "private-remote-session-cancel"
                );
                let mut reply = Reply::body("");
                reply.status = ack_status;
                reply
            }
            _ => panic!("unexpected fixture method"),
        };
        reply
            .headers
            .push(("content-type".into(), "application/json".into()));
        reply
    })
    .await;
    (fixture, entered)
}

#[tokio::test]
async fn remote_mcp_cancel_ignores_unknown_and_completed_ids_without_store_access() {
    let fixture = fixture(false, false).await;
    let broker = Broker::new(configuration(&fixture)).unwrap();
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    response_json(session.execute(request(&fixture, call())).await.unwrap()).await;
    fixture.store.lock().await.unwrap();
    for id in [
        json!("unknown"),
        json!("agent-call"),
        json!("agent-initialize"),
    ] {
        empty_accepted(
            session
                .execute(request(&fixture, notification(id)))
                .await
                .expect("ignored MCP cancellation must not access the locked store"),
        )
        .await;
    }
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn remote_mcp_cancel_dispatches_one_owned_notification_without_replay() {
    for via_mcp in [true, false] {
        let (fixture, entered) = slow_fixture().await;
        let broker = Broker::new(configuration(&fixture)).unwrap();
        let session = broker.create_session(options()).unwrap();
        handshake(&fixture, &session).await;
        let input = request(&fixture, call());
        let task = tokio::spawn({
            let (session, input) = (session.clone(), input.clone());
            async move { session.execute(input).await }
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        if via_mcp {
            empty_accepted(
                session
                    .execute(request(&fixture, notification(json!("agent-call"))))
                    .await
                    .unwrap(),
            )
            .await;
        } else {
            assert_eq!(
                session
                    .cancel(input.request_id.clone())
                    .await
                    .unwrap()
                    .state,
                OperationState::OutcomeUnknown
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(
            fixture.origin.requests.lock().unwrap().len(),
            4,
            "cancel must make one mapped upstream notification"
        );
        assert_eq!(
            session
                .request_status(input.request_id.clone())
                .await
                .unwrap()
                .state,
            OperationState::OutcomeUnknown
        );
        session.cancel(input.request_id.clone()).await.unwrap();
        empty_accepted(
            session
                .execute(request(&fixture, notification(json!("agent-call"))))
                .await
                .unwrap(),
        )
        .await;
        let duplicate = session.execute(input).await.unwrap();
        assert_eq!(duplicate.headers()["x-aap-operation-state"], "existing");
        drop(duplicate);
        assert_eq!(
            fixture.origin.requests.lock().unwrap().len(),
            4,
            "duplicate cancellation or status must not redispatch"
        );
        let records = fixture.recorder.read(None, 256).unwrap().records;
        assert!(
            records
                .iter()
                .any(|record| record.event.parent_request_id.is_some()),
            "cancellation needs a correlated child flow"
        );
        for record in records {
            let metadata = serde_json::to_string(&record).unwrap();
            assert!(!metadata.contains("private-remote-session"));
            if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
                let bytes = STANDARD.decode(body_base64).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains("untrusted cancellation reason"));
                assert!(!text.contains("private-remote-session"));
            }
        }
    }
}

struct HoldToolApproval {
    entered: Arc<tokio::sync::Notify>,
    calls: AtomicUsize,
}
impl ApprovalProvider for HoldToolApproval {
    fn approve(
        &self,
        request: Arc<ApprovalRequest>,
        _: Cancellation,
    ) -> BoxFuture<'_, Result<bool>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let body = STANDARD.decode(&request.operation.body_base64).unwrap();
            let message: Value = serde_json::from_slice(&body).unwrap();
            if message["method"] == "tools/call" {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(true)
        })
    }
}

#[tokio::test]
async fn remote_mcp_cancel_pending_approval_is_local_even_when_store_locks() {
    for via_mcp in [true, false] {
        let fixture = fixture(false, false).await;
        let mut config = configuration(&fixture);
        let entered = Arc::new(tokio::sync::Notify::new());
        let approval = Arc::new(HoldToolApproval {
            entered: entered.clone(),
            calls: AtomicUsize::new(0),
        });
        config.catalog.items[0].approval = ItemApproval::Always;
        config.approval = Some(approval.clone());
        let broker = Broker::new(config).unwrap();
        let session = broker.create_session(options()).unwrap();
        handshake(&fixture, &session).await;
        let input = request(&fixture, call());
        let task = tokio::spawn({
            let (session, input) = (session.clone(), input.clone());
            async move { session.execute(input).await }
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        fixture.store.lock().await.unwrap();
        let cancel = if via_mcp {
            session
                .execute(request(&fixture, notification(json!("agent-call"))))
                .await
                .map(Some)
        } else {
            session.cancel(input.request_id.clone()).await.map(|_| None)
        };
        if cancel.is_err() {
            task.abort();
        }
        if let Some(response) = cancel.expect("local cancellation must not depend on store access")
        {
            empty_accepted(response).await;
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(
            session
                .request_status(input.request_id)
                .await
                .unwrap()
                .state,
            OperationState::Cancelled
        );
        assert_eq!(approval.calls.load(Ordering::SeqCst), 3);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    }
}

struct ApproveAll(AtomicUsize);
impl ApprovalProvider for ApproveAll {
    fn approve(&self, _: Arc<ApprovalRequest>, _: Cancellation) -> BoxFuture<'_, Result<bool>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(true) })
    }
}

#[tokio::test]
async fn remote_mcp_cancel_is_local_when_remote_cleanup_is_not_permitted() {
    for mode in ["approval", "capacity", "locked", "refused"] {
        for via_mcp in [true, false] {
            let (fixture, entered) =
                slow_fixture_with_ack(if mode == "refused" { 404 } else { 202 }).await;
            let mut config = configuration(&fixture);
            let approvals = Arc::new(ApproveAll(AtomicUsize::new(0)));
            if mode == "approval" {
                config.catalog.items[0].approval = ItemApproval::Always;
                config.approval = Some(approvals.clone());
            }
            let broker = Broker::new(config).unwrap();
            let session = broker.create_session(options()).unwrap();
            handshake(&fixture, &session).await;
            let input = request(&fixture, call());
            let task = tokio::spawn({
                let (session, input) = (session.clone(), input.clone());
                async move { session.execute(input).await }
            });
            tokio::time::timeout(Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            let _capacity = if mode == "capacity" {
                Some(
                    session
                        .core
                        .control
                        .clone()
                        .acquire_many_owned(2)
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            if mode == "locked" {
                fixture.store.lock().await.unwrap();
            }
            if via_mcp {
                empty_accepted(
                    session
                        .execute(request(&fixture, notification(json!("agent-call"))))
                        .await
                        .unwrap(),
                )
                .await;
            } else {
                session.cancel(input.request_id.clone()).await.unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert_eq!(
                session
                    .request_status(input.request_id)
                    .await
                    .unwrap()
                    .state,
                OperationState::OutcomeUnknown
            );
            let expected = if mode == "refused" { 4 } else { 3 };
            assert_eq!(
                fixture.origin.requests.lock().unwrap().len(),
                expected,
                "mode {mode}"
            );
            assert_eq!(
                fixture.resolutions.load(Ordering::SeqCst),
                expected,
                "mode {mode}"
            );
            if mode == "approval" {
                assert_eq!(
                    approvals.0.load(Ordering::SeqCst),
                    3,
                    "cancellation cannot initiate a fresh human approval"
                );
            }
        }
    }
}

#[tokio::test]
async fn remote_mcp_cancel_initialization_retires_context_before_response_drop() {
    let fixture = fixture(false, false).await;
    let mut config = configuration(&fixture);
    // Retain the cancelled response while admitting its replacement. Both
    // conservative response reservations must fit the unchanged shared budget.
    config.profiles[0].routes[0].max_response_bytes = 256 * 1024;
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(options()).unwrap();
    let input = request(&fixture, initialize());
    let held = session.execute(input.clone()).await.unwrap();
    empty_accepted(
        session
            .execute(request(&fixture, notification(json!("agent-initialize"))))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        session
            .request_status(input.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::Dispatching,
        "MCP initialization cancellation must be ignored"
    );
    session.cancel(input.request_id.clone()).await.unwrap();
    assert_eq!(
        fixture.origin.requests.lock().unwrap().len(),
        1,
        "initialization cannot receive an upstream cancellation"
    );
    handshake(&fixture, &session).await;
    assert!(held.into_body().collect().await.is_err());
    assert_eq!(
        session
            .request_status(input.request_id)
            .await
            .unwrap()
            .state,
        OperationState::OutcomeUnknown
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
}
