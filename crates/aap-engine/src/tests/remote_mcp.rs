use super::*;
use aap_types::mcp::{Argument, Tool, VERSION};
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use std::collections::BTreeMap;

mod cancellation;
mod cleanup;
mod controls;

fn tools() -> Vec<Tool> {
    vec![Tool {
        name: "echo".into(),
        description: "Reviewed echo".into(),
        arguments: BTreeMap::from([("text".into(), Argument::Text { max_length: 1024 })]),
    }]
}

async fn fixture(sse: bool, disconnect_call: bool) -> Fixture {
    let mut fixture = Fixture::new().await;
    let contexts = Mutex::new(HashMap::<String, bool>::new());
    fixture.origin = Origin::with_handler(move |request| {
        assert_eq!(request.target.path(), "/mcp");
        assert_eq!(request.headers["authorization"], "Bearer synthetic-api-key");
        let input: Value = serde_json::from_slice(&request.body).unwrap();
        let mut contexts = contexts.lock().unwrap();
        let method = input["method"].as_str().unwrap();
        let mut native = None;
        let result = if method == "initialize" {
            assert!(!request.headers.contains_key("mcp-session-id"));
            assert_eq!(input["params"]["capabilities"], json!({}));
            let id = format!("private-remote-session-{}", contexts.len() + 1);
            contexts.insert(id.clone(), false);
            native = Some(id);
            json!({"protocolVersion":VERSION,"capabilities":{"tools":{}},
                "serverInfo":{"name":"untrusted-info","version":"1"}})
        } else {
            let id = request.headers["mcp-session-id"].to_str().unwrap();
            assert_eq!(request.headers["mcp-protocol-version"], VERSION);
            let ready = contexts.get_mut(id).unwrap();
            if method == "notifications/initialized" {
                assert!(!*ready);
                *ready = true;
                let mut reply = Reply::body(Bytes::new());
                reply.status = 202;
                return reply;
            }
            assert!(*ready);
            match method {
                "tools/list" => json!({"tools":tools().iter().map(Tool::definition).collect::<Vec<_>>()}),
                "tools/call" => {
                    if disconnect_call {
                        let mut reply = Reply::body(Bytes::new());
                        reply.disconnect = true;
                        return reply;
                    }
                    json!({"content":[{"type":"text","text":format!("{} synthetic-api-key {id}",input["params"]["arguments"]["text"].as_str().unwrap())}]})
                }
                _ => panic!("unhandled fixture message"),
            }
        };
        let body = json!({"jsonrpc":"2.0","id":input["id"],"result":result}).to_string();
        let mut reply = Reply::body(if sse {format!("data: {body}\n\n")} else {body});
        reply.headers.push(("content-type".into(), if sse {"text/event-stream"} else {"application/json"}.into()));
        if let Some(id) = native {reply.headers.push(("mcp-session-id".into(),id));}
        // Exercise boundaries in actual network bodies, not only pure decoders.
        let body = reply.chunks.pop().unwrap();
        reply.chunks = body.chunks(7).map(Bytes::copy_from_slice).collect();
        reply
    }).await;
    fixture
}

fn configuration(fixture: &Fixture) -> Configuration {
    let mut config = fixture.configuration();
    let profile = &mut config.profiles[0];
    profile.routes[0].path = "/mcp".into();
    profile.routes[0].streaming = false;
    profile.routes[0].max_request_bytes = aap_types::mcp::MAX_REQUEST;
    profile.routes[0].allowed_headers = vec![
        "content-type".into(),
        "accept".into(),
        "mcp-protocol-version".into(),
    ];
    profile.auth = Authentication::Mcp {
        item_id: "provider-key".into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        tools: tools(),
    };
    config
}
fn request(fixture: &Fixture, message: Value) -> ExecuteRequest {
    let mut request = fixture.request();
    request.target = format!("{}/mcp", fixture.origin.origin());
    request.body_base64 = STANDARD.encode(serde_json::to_vec(&message).unwrap());
    request
}
fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":"agent-initialize","method":"initialize",
        "params":{"protocolVersion":VERSION,"capabilities":{"sampling":{}},
            "clientInfo":{"name":"untrusted-agent-info","version":"1"}}})
}
fn call() -> Value {
    json!({"jsonrpc":"2.0","id":"agent-call","method":"tools/call",
        "params":{"name":"echo","arguments":{"text":"hello"}}})
}
async fn response_json(response: Response) -> Value {
    assert!(!response.headers().contains_key("mcp-session-id"));
    assert!(!response.headers().contains_key("set-cookie"));
    let sse = response
        .headers()
        .get("content-type")
        .is_some_and(|v| v == "text/event-stream");
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("MCP response completion")
        .to_bytes();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("synthetic-api-key"));
    assert!(!text.contains("private-remote-session"));
    serde_json::from_str(if sse {
        text.strip_prefix("data: ").unwrap().trim_end()
    } else {
        text
    })
    .unwrap()
}
async fn handshake(fixture: &Fixture, session: &Session) {
    let result = response_json(
        session
            .execute(request(fixture, initialize()))
            .await
            .expect("remote MCP initialization"),
    )
    .await;
    assert_eq!(result["id"], "agent-initialize");
    assert_eq!(result["result"]["capabilities"], json!({"tools":{}}));
    let response = session
        .execute(request(
            fixture,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        ))
        .await
        .unwrap();
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

#[tokio::test]
async fn remote_mcp_json_and_sse_use_private_contexts_and_real_tls() {
    for sse in [false, true] {
        let fixture = fixture(sse, false).await;
        let broker = Broker::new(configuration(&fixture)).unwrap();
        let first = broker.create_session(options()).unwrap();
        let second = broker.create_session(options()).unwrap();
        for session in [&first, &second] {
            assert!(session.execute(request(&fixture, call())).await.is_err());
            handshake(&fixture, session).await;
            let list = response_json(
                session
                    .execute(request(
                        &fixture,
                        json!({"jsonrpc":"2.0","id":"agent-list","method":"tools/list"}),
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(list["result"]["tools"][0]["description"], "Reviewed echo");
            let input = request(&fixture, call());
            let result = response_json(session.execute(input.clone()).await.unwrap()).await;
            assert_eq!(result["id"], "agent-call");
            assert_eq!(
                result["result"]["content"][0]["text"],
                "hello [redacted] [redacted]"
            );
            assert_eq!(
                session
                    .request_status(input.request_id)
                    .await
                    .unwrap()
                    .state,
                OperationState::Completed
            );
        }
        let requests = fixture.origin.requests.lock().unwrap();
        assert_eq!(requests.len(), 8);
        assert_ne!(
            requests[1].headers["mcp-session-id"],
            requests[5].headers["mcp-session-id"]
        );
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 8);
        for record in fixture.recorder.read(None, 256).unwrap().records {
            let encoded = serde_json::to_string(&record).unwrap();
            assert!(!encoded.contains("private-remote-session"));
            assert!(!encoded.contains("synthetic-api-key"));
            if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
                let content = STANDARD.decode(body_base64).unwrap();
                let content = String::from_utf8_lossy(&content);
                assert!(!content.contains("private-remote-session"));
                assert!(!content.contains("synthetic-api-key"));
            }
        }
    }
}

#[tokio::test]
async fn remote_mcp_requires_completed_handshake_and_rejects_invalid_calls_before_secrets() {
    let fixture = fixture(false, false).await;
    let broker = Broker::new(configuration(&fixture)).unwrap();
    let session = broker.create_session(options()).unwrap();
    let held = session
        .execute(request(&fixture, initialize()))
        .await
        .expect("remote MCP initialization");
    assert!(
        session
            .execute(request(
                &fixture,
                json!({"jsonrpc":"2.0","method":"notifications/initialized"})
            ))
            .await
            .is_err()
    );
    assert!(session.execute(request(&fixture, call())).await.is_err());
    drop(held);
    handshake(&fixture, &session).await;
    let before = fixture.resolutions.load(Ordering::SeqCst);
    for message in [
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"not-enrolled","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"ok","extra":true}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"sampling/createMessage","params":{}}),
    ] {
        assert!(session.execute(request(&fixture, message)).await.is_err());
    }
    for (name, value) in [
        ("mcp-session-id", "forged"),
        ("mcp-protocol-version", "wrong"),
        ("last-event-id", "resume"),
    ] {
        let mut input = request(&fixture, call());
        input.headers.push((name.into(), value.into()));
        assert!(session.execute(input).await.is_err());
    }
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), before);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn remote_mcp_uncertain_calls_are_never_replayed_by_status_or_duplicates() {
    let fixture = fixture(false, true).await;
    let broker = Broker::new(configuration(&fixture)).unwrap();
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    let input = request(&fixture, call());
    assert!(session.execute(input.clone()).await.is_err());
    assert_eq!(
        session
            .request_status(input.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::OutcomeUnknown
    );
    let response = session.execute(input).await.unwrap();
    assert_eq!(response.headers()["x-aap-operation-state"], "existing");
    let _ = response.into_body().collect().await.unwrap();
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
}

async fn rotate(fixture: &Fixture) {
    let reference = ItemRef::new("private-reference".into()).unwrap();
    let metadata = fixture.store.metadata(&reference).await.unwrap();
    fixture
        .store
        .put(
            &reference,
            [(
                Field::ApiKey,
                SecretBytes::new(b"synthetic-api-key".to_vec()).unwrap(),
            )]
            .into(),
            Some(&metadata.lease),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn remote_mcp_approval_binds_generation_without_resolving_a_password() {
    for outcome in ["approve", "rotate", "cancel", "revoke"] {
        let fixture = fixture(false, false).await;
        let (received_tx, mut received) = tokio::sync::mpsc::unbounded_channel();
        let (decision, decision_rx) = tokio::sync::oneshot::channel();
        let mut config = configuration(&fixture);
        config.require_approval = true;
        config.approval = Some(Arc::new(Gate {
            received: received_tx,
            decision: Mutex::new(Some(decision_rx)),
        }));
        let broker = Broker::new(config).unwrap();
        let session = broker.create_session(options()).unwrap();
        let input = request(&fixture, initialize());
        let id = input.request_id.clone();
        let running = session.clone();
        let task = tokio::spawn(async move { running.execute(input).await });
        let approval = tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.operation.request_id, id);
        assert!(aap_types::ids::valid_id(
            approval
                .context_id
                .as_deref()
                .expect("MCP approval lacks a context generation"),
            16
        ));
        assert_eq!(
            session.request_status(id.clone()).await.unwrap().state,
            OperationState::PendingApproval
        );
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        assert!(fixture.origin.requests.lock().unwrap().is_empty());
        match outcome {
            "rotate" => rotate(&fixture).await,
            "cancel" => {
                assert_eq!(
                    session.cancel(id).await.unwrap().state,
                    OperationState::Cancelled
                );
            }
            "revoke" => broker.revoke(&session).unwrap(),
            _ => {}
        }
        let _ = decision.send(true);
        let result = task.await.unwrap();
        if outcome == "approve" {
            let _ = response_json(result.unwrap()).await;
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
        } else {
            assert!(result.is_err());
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
            assert!(fixture.origin.requests.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn remote_mcp_rechecks_custody_before_delivery_and_never_revives_old_contexts() {
    for delivery_started in [false, true] {
        let fixture = fixture(false, false).await;
        let broker = Broker::new(configuration(&fixture)).unwrap();
        let session = broker.create_session(options()).unwrap();
        handshake(&fixture, &session).await;
        let input = request(&fixture, call());
        let held = session.execute(input.clone()).await.unwrap();
        let mut body = held.into_body();
        if delivery_started {
            let frame = body.frame().await.unwrap().unwrap();
            assert!(frame.data_ref().is_some());
        }
        rotate(&fixture).await;
        assert!(body.collect().await.is_err());
        assert_eq!(
            session
                .request_status(input.request_id)
                .await
                .unwrap()
                .state,
            OperationState::OutcomeUnknown
        );
        assert!(session.execute(request(&fixture, call())).await.is_err());
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
        handshake(&fixture, &session).await;
        let _ = response_json(session.execute(request(&fixture, call())).await.unwrap()).await;
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 6);
    }
}

struct ResolveFailure {
    inner: Arc<dyn SecretStore>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}
impl SecretStore for ResolveFailure {
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
        self.inner.revalidate(item, lease)
    }
    fn resolve<'a>(
        &'a self,
        item: &'a ItemRef,
        lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::Snapshot>> {
        if self.fail.load(Ordering::SeqCst) {
            Box::pin(async { Err(aap_secrets::StoreError::AccessDenied) })
        } else {
            self.inner.resolve(item, lease)
        }
    }
}

#[tokio::test]
async fn remote_mcp_failed_secret_resolution_invalidates_existing_session_authority() {
    let fixture = fixture(false, false).await;
    let mut config = configuration(&fixture);
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    config.stores.insert(
        "default".into(),
        Arc::new(ResolveFailure {
            inner: config.stores["default"].clone(),
            fail: fail.clone(),
        }),
    );
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    fail.store(true, Ordering::SeqCst);
    assert!(session.execute(request(&fixture, call())).await.is_err());
    fail.store(false, Ordering::SeqCst);
    assert!(
        session.execute(request(&fixture, call())).await.is_err(),
        "failed secret resolution left the old MCP session usable"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    handshake(&fixture, &session).await;
    let _ = response_json(session.execute(request(&fixture, call())).await.unwrap()).await;
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 5);
}

struct AddTrailers {
    inner: HttpsTransport,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}
impl Transport for AddTrailers {
    fn execute(
        &self,
        endpoint: aap_transport::Endpoint,
        request: http::Request<Bytes>,
        limits: aap_transport::Limits,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move {
            let response = self
                .inner
                .execute(endpoint, request, limits, cancellation)
                .await?;
            if self.enabled.load(Ordering::SeqCst) {
                Ok(response.map(|inner| {
                    TrailingBody {
                        inner,
                        emitted: false,
                    }
                    .boxed_unsync()
                }))
            } else {
                Ok(response)
            }
        })
    }
}
struct TrailingBody {
    inner: aap_types::Body,
    emitted: bool,
}
impl http_body::Body for TrailingBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>>>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_frame(context) {
            std::task::Poll::Ready(None) if !this.emitted => {
                this.emitted = true;
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    "set-cookie",
                    http::HeaderValue::from_static("hidden=private-trailer"),
                );
                std::task::Poll::Ready(Some(Ok(http_body::Frame::trailers(headers))))
            }
            result => result,
        }
    }
}

#[tokio::test]
async fn remote_mcp_rejected_trailers_invalidate_the_context_before_delivery() {
    let fixture = fixture(false, false).await;
    let mut config = configuration(&fixture);
    let enabled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    config.transport = Arc::new(AddTrailers {
        inner: HttpsTransport::new([fixture.origin.certificate.clone()]).unwrap(),
        enabled: enabled.clone(),
    });
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    enabled.store(true, Ordering::SeqCst);
    assert!(session.execute(request(&fixture, call())).await.is_err());
    enabled.store(false, Ordering::SeqCst);
    assert!(
        session.execute(request(&fixture, call())).await.is_err(),
        "rejected trailers left private MCP session authority active"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    handshake(&fixture, &session).await;
    let _ = response_json(session.execute(request(&fixture, call())).await.unwrap()).await;
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 6);
}
