use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completion_gate_rejects_late_local_cleanup_success() {
    use crate::tests::{
        completion::{incomplete_endings, retire_at_completion},
        dispatch::EndAuthority,
    };
    let fixture = fixture(204, "", true).await;
    let broker = Arc::new(Broker::new(config(&fixture)).unwrap());
    let session = broker.create_session(options()).unwrap();
    // No native context: local DELETE must not invent an upstream dispatch.
    closed(session.execute(delete(&fixture)).await.unwrap(), "skipped").await;
    let input = delete(&fixture);
    let id = input.request_id.clone();
    let running = session.clone();
    let (result, status) =
        retire_at_completion(broker, &session, EndAuthority::Broker, async move {
            running.execute(input).await
        })
        .await;
    assert!(result.is_err());
    assert_eq!(status.state, OperationState::Cancelled);
    incomplete_endings(&fixture, &id);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_dispatch_gate_blocks_closed_remote_control_handoff() {
    use crate::tests::dispatch::{CountedTransport, EndAuthority, close_at_ready};
    let fixture = fixture(204, "", true).await;
    let mut configuration = config(&fixture);
    let calls = CountedTransport::install(&mut configuration);
    let broker = Arc::new(Broker::new(configuration).unwrap());
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    closed(
        session.execute(delete(&fixture)).await.unwrap(),
        "confirmed",
    )
    .await;
    handshake(&fixture, &session).await;
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 5);
    let input = delete(&fixture);
    let parent = input.request_id.clone();
    let running = session.clone();
    let (result, status) = close_at_ready(broker, &session, EndAuthority::Broker, async move {
        running.execute(input).await
    })
    .await;
    assert!(result.is_err());
    assert_ne!(status.request_id, parent, "must exercise the control child");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "closed authority handed an MCP cleanup request to the transport"
    );
    assert_eq!(status.state, OperationState::Cancelled);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 5);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn broker_close_during_resolution_discards_the_returned_cleanup_key() {
    use crate::tests::lifecycle::{CloseAt, ClosingStore, no_authentication_prepared};
    let fixture = fixture(204, "", true).await;
    let mut configuration = config(&fixture);
    let store = ClosingStore::install(&mut configuration);
    let broker = Arc::new(Broker::new(configuration).unwrap());
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    closed(
        session.execute(delete(&fixture)).await.unwrap(),
        "confirmed",
    )
    .await;
    handshake(&fixture, &session).await;
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 5);
    store.arm(&broker, CloseAt::Resolve);
    let input = delete(&fixture);
    let id = input.request_id.clone();
    assert!(session.execute(input).await.is_err());
    assert!(broker.is_closed());
    no_authentication_prepared(&fixture, &id);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 5);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 6);
}

async fn fixture(status: u16, body: &'static str, native: bool) -> Fixture {
    let mut fixture = Fixture::new().await;
    let next = AtomicUsize::new(0);
    fixture.origin = Origin::with_handler(move |request| {
        assert_eq!(request.headers["authorization"], "Bearer synthetic-api-key");
        if request.method == "DELETE" {
            assert!(native, "stateless context must not dispatch DELETE");
            assert!(request.body.is_empty());
            assert!(request.headers["mcp-session-id"].to_str().unwrap().starts_with("private-remote-session-cleanup-"));
            assert_eq!(request.headers["mcp-protocol-version"], VERSION);
            let mut reply = Reply::body(body);
            reply.status = status;
            return reply;
        }
        let message: Value = serde_json::from_slice(&request.body).unwrap();
        let mut session = None;
        let result = match message["method"].as_str().unwrap() {
            "initialize" => {
                assert!(!request.headers.contains_key("mcp-session-id"));
                if native {
                    session = Some(format!("private-remote-session-cleanup-{}", next.fetch_add(1, Ordering::SeqCst)));
                }
                json!({"protocolVersion":VERSION,"capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}})
            }
            "notifications/initialized" => {
                let mut reply = Reply::body("");
                reply.status = 202;
                return reply;
            }
            "tools/call" => json!({"content":[{"type":"text","text":"ok"}]}),
            _ => panic!("unexpected fixture method"),
        };
        let mut reply = Reply::body(json!({"jsonrpc":"2.0","id":message["id"],"result":result}).to_string());
        reply.headers.push(("content-type".into(), "application/json".into()));
        if let Some(session) = session { reply.headers.push(("mcp-session-id".into(), session)); }
        reply
    }).await;
    fixture
}
fn config(fixture: &Fixture) -> Configuration {
    let mut config = configuration(fixture);
    let mut delete = config.profiles[0].routes[0].clone();
    delete.method = "DELETE".into();
    delete.allowed_headers.clear();
    config.profiles[0].routes.push(delete);
    config
}
fn delete(fixture: &Fixture) -> ExecuteRequest {
    let mut request = request(fixture, json!({}));
    request.method = "DELETE".into();
    request.headers.clear();
    request.body_base64.clear();
    request
}
async fn closed(response: Response, expected: &str) {
    assert_eq!(response.status(), 204);
    assert_eq!(response.headers()["x-aap-remote-cleanup"], expected);
    assert!(!response.headers().contains_key("mcp-session-id"));
    assert!(!response.headers().contains_key("set-cookie"));
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

#[tokio::test]
async fn remote_mcp_delete_closes_locally_and_reports_cleanup_without_replay() {
    for (status, body, outcome) in [
        (204, "", "confirmed"),
        (200, "", "confirmed"),
        (405, "", "not_supported"),
        (500, "synthetic-api-key", "unknown"),
        (200, "unexpected", "unknown"),
        (202, "", "unknown"),
    ] {
        let fixture = fixture(status, body, true).await;
        let broker = Broker::new(config(&fixture)).unwrap();
        let session = broker.create_session(options()).unwrap();
        closed(
            session
                .execute(delete(&fixture))
                .await
                .expect("local MCP DELETE"),
            "skipped",
        )
        .await;
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        handshake(&fixture, &session).await;
        let input = delete(&fixture);
        closed(session.execute(input.clone()).await.unwrap(), outcome).await;
        assert_eq!(
            session
                .request_status(input.request_id.clone())
                .await
                .unwrap()
                .state,
            OperationState::Completed
        );
        assert!(session.execute(request(&fixture, call())).await.is_err());
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 3);
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
        let duplicate = session.execute(input).await.unwrap();
        assert_eq!(duplicate.headers()["x-aap-operation-state"], "existing");
        drop(duplicate);
        closed(session.execute(delete(&fixture)).await.unwrap(), "skipped").await;
        handshake(&fixture, &session).await;
        response_json(session.execute(request(&fixture, call())).await.unwrap()).await;
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 6);
        let records = fixture.recorder.read(None, 256).unwrap().records;
        assert!(
            records
                .iter()
                .any(|record| record.event.parent_request_id.is_some())
        );
        for record in records {
            let metadata = serde_json::to_string(&record).unwrap();
            assert!(!metadata.contains("private-remote-session"));
            if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
                let bytes = STANDARD.decode(body_base64).unwrap();
                assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-api-key"));
            }
        }
    }
}

struct ApproveAll;
impl ApprovalProvider for ApproveAll {
    fn approve(
        &self,
        request: Arc<ApprovalRequest>,
        _: Cancellation,
    ) -> BoxFuture<'_, Result<bool>> {
        assert_ne!(
            request.operation.method, "DELETE",
            "cleanup cannot start a human wait"
        );
        Box::pin(async { Ok(true) })
    }
}

#[tokio::test]
async fn remote_mcp_delete_needs_no_store_or_approval_to_close_local_authority() {
    for mode in ["locked", "rotated", "approval", "capacity", "stateless"] {
        let fixture = fixture(204, "", mode != "stateless").await;
        let mut config = config(&fixture);
        if mode == "approval" {
            config.catalog.items[0].approval = ItemApproval::Always;
            config.approval = Some(Arc::new(ApproveAll));
        }
        let broker = Broker::new(config).unwrap();
        let session = broker.create_session(options()).unwrap();
        handshake(&fixture, &session).await;
        if mode == "locked" {
            fixture.store.lock().await.unwrap();
        }
        if mode == "rotated" {
            rotate(&fixture).await;
        }
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
        closed(
            session
                .execute(delete(&fixture))
                .await
                .expect("local closure cannot require remote authority"),
            "skipped",
        )
        .await;
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
        if mode == "locked" {
            fixture
                .store
                .unlock(SecretBytes::new(vec![17; 32]).unwrap())
                .await
                .unwrap();
        }
        assert!(session.execute(request(&fixture, call())).await.is_err());
    }
}

struct HoldDelete {
    inner: HttpsTransport,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl Transport for HoldDelete {
    fn execute(
        &self,
        endpoint: aap_transport::Endpoint,
        request: http::Request<Bytes>,
        limits: aap_transport::Limits,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move {
            if request.method() == "DELETE" {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.inner
                .execute(endpoint, request, limits, cancellation)
                .await
        })
    }
}

#[tokio::test]
async fn remote_mcp_delete_revokes_before_cleanup_and_blocks_overlapping_reinitialization() {
    let fixture = fixture(204, "", true).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let mut config = config(&fixture);
    config.profiles[0].routes[0].max_response_bytes = 256 * 1024;
    config.transport = Arc::new(HoldDelete {
        inner: HttpsTransport::new([fixture.origin.certificate.clone()]).unwrap(),
        entered: entered.clone(),
        release: release.clone(),
    });
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    let held = session.execute(request(&fixture, call())).await.unwrap();
    let task = tokio::spawn({
        let (session, input) = (session.clone(), delete(&fixture));
        async move { session.execute(input).await }
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("cleanup dispatch");
    assert!(
        held.into_body().collect().await.is_err(),
        "DELETE must immediately revoke outstanding delivery"
    );
    assert!(session.execute(request(&fixture, call())).await.is_err());
    // Another close must not steal/release the first attempt's barrier.
    closed(session.execute(delete(&fixture)).await.unwrap(), "skipped").await;
    assert!(
        matches!(session.execute(request(&fixture, initialize())).await, Err(error) if error.code == ErrorCode::RequestConflict)
    );
    release.notify_one();
    closed(task.await.unwrap().unwrap(), "confirmed").await;
    handshake(&fixture, &session).await;
}

#[tokio::test]
async fn remote_mcp_delete_barrier_ends_on_timeout_drop_and_child_cancellation() {
    for mode in ["timeout", "drop", "child_cancel"] {
        let fixture = fixture(204, "", true).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut config = config(&fixture);
        config.transport = Arc::new(HoldDelete {
            inner: HttpsTransport::new([fixture.origin.certificate.clone()]).unwrap(),
            entered: entered.clone(),
            release,
        });
        let broker = Broker::new(config).unwrap();
        let session = broker.create_session(options()).unwrap();
        handshake(&fixture, &session).await;
        let input = delete(&fixture);
        let mut task = tokio::spawn({
            let (session, input) = (session.clone(), input.clone());
            async move { session.execute(input).await }
        });
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        let child = fixture
            .recorder
            .read(None, 256)
            .unwrap()
            .records
            .into_iter()
            .find(|record| record.event.parent_request_id.as_ref() == Some(&input.request_id))
            .unwrap()
            .event
            .request_id
            .unwrap();
        if mode == "drop" {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            if mode == "child_cancel" {
                assert_eq!(
                    session.cancel(child.clone()).await.unwrap().state,
                    OperationState::OutcomeUnknown
                );
            } else {
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(3)).await;
                tokio::time::resume();
            }
            let result = tokio::time::timeout(Duration::from_millis(500), &mut task).await;
            task.abort();
            closed(
                result
                    .expect("cleanup must stop promptly")
                    .unwrap()
                    .unwrap(),
                "unknown",
            )
            .await;
        }
        assert_eq!(
            session.request_status(child).await.unwrap().state,
            OperationState::OutcomeUnknown
        );
        assert_eq!(
            fixture.origin.requests.lock().unwrap().len(),
            2,
            "held child must never reach fixture"
        );
        assert!(session.execute(request(&fixture, call())).await.is_err());
        handshake(&fixture, &session).await;
        response_json(session.execute(request(&fixture, call())).await.unwrap()).await;
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 5);
    }
}
