use super::*;
use aap_client::DaemonSessionClient;
use aap_types::mcp::{Argument, Tool, VERSION};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

fn tools() -> Vec<Tool> {
    vec![Tool {
        name: "echo".into(),
        description: "Reviewed echo".into(),
        arguments: BTreeMap::from([("text".into(), Argument::Text { max_length: 1024 })]),
    }]
}
fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":"agent-init","method":"initialize","params":{
        "protocolVersion":VERSION,"capabilities":{"sampling":{}},"clientInfo":{"name":"fixture","version":"1"}}})
}
fn initialized() -> Value {
    json!({"jsonrpc":"2.0","method":"notifications/initialized"})
}
fn call(text: &str) -> Value {
    json!({"jsonrpc":"2.0","id":"agent-call","method":"tools/call","params":{"name":"echo","arguments":{"text":text}}})
}
fn input(fixture: &Fixture, resource: &str, message: Value) -> ExecuteRequest {
    ExecuteRequest {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: resource.into(),
        auth_context: None,
        method: "POST".into(),
        target: format!("{}/mcp", fixture.origin.origin()),
        headers: vec![("content-type".into(), "application/json".into())],
        body_base64: STANDARD.encode(serde_json::to_vec(&message).unwrap()),
    }
}
fn delete(fixture: &Fixture, resource: &str) -> ExecuteRequest {
    let mut input = input(fixture, resource, json!({}));
    input.method = "DELETE".into();
    input.headers.clear();
    input.body_base64.clear();
    input
}
fn safe(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    for value in [
        "synthetic-daemon-key",
        "synthetic-second-key",
        "private-daemon-mcp",
        "private-server-ping",
    ] {
        assert!(!text.contains(value), "private remote state escaped");
    }
}
fn decoded(bytes: &[u8]) -> Value {
    safe(bytes);
    if bytes.starts_with(b"data:") {
        let text = std::str::from_utf8(bytes).unwrap();
        let lines: Vec<_> = text
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "private server ping must not appear as an agent event"
        );
        serde_json::from_str(lines[0]).unwrap()
    } else {
        serde_json::from_slice(bytes).unwrap()
    }
}
async fn response(response: aap_types::Response) -> Value {
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("mcp-session-id"));
    assert!(!response.headers().contains_key("set-cookie"));
    decoded(&response.into_body().collect().await.unwrap().to_bytes())
}
async fn handshake(fixture: &Fixture, client: &DaemonSessionClient, resource: &str) {
    let value = response(
        client
            .execute(input(fixture, resource, initialize()))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(value["id"], "agent-init");
    assert_eq!(value["result"]["protocolVersion"], VERSION);
    let response = client
        .execute(input(fixture, resource, initialized()))
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
async fn fixture(sse: bool) -> Fixture {
    let mut fixture = Fixture::new().await;
    let sessions = Mutex::new(HashMap::<String, (&'static str, bool)>::new());
    let next = AtomicUsize::new(0);
    fixture.origin = Origin::with_handler(move |request| {
        assert_eq!(request.target.path(), "/mcp");
        let (account, key) = match request.headers["authorization"].to_str().unwrap() {
            "Bearer synthetic-daemon-key" => ("first", "synthetic-daemon-key"),
            "Bearer synthetic-second-key" => ("second", "synthetic-second-key"),
            _ => panic!("missing enrolled credential"),
        };
        let mut sessions = sessions.lock().unwrap();
        if request.method == "DELETE" {
            assert!(request.body.is_empty());
            assert_eq!(request.headers["mcp-protocol-version"], VERSION);
            let native = request.headers["mcp-session-id"].to_str().unwrap();
            assert_eq!(sessions.remove(native).unwrap().0, account);
            let mut reply = Reply::body(""); reply.status = 204; return reply;
        }
        assert_eq!(request.method, "POST");
        let message: Value = serde_json::from_slice(&request.body).unwrap();
        if message.get("method").is_none() {
            assert_eq!(message["id"], "private-server-ping");
            assert_eq!(message["result"], json!({}));
            assert_eq!(sessions[request.headers["mcp-session-id"].to_str().unwrap()].0, account);
            let mut reply = Reply::body(""); reply.status = 202; return reply;
        }
        let mut created = None;
        let result = if message["method"] == "initialize" {
            assert!(!request.headers.contains_key("mcp-session-id"));
            assert_ne!(message["id"], "agent-init");
            assert_eq!(message["params"]["capabilities"], json!({}));
            let native = format!("private-daemon-mcp-{}", next.fetch_add(1, Ordering::SeqCst));
            sessions.insert(native.clone(), (account, false)); created = Some(native);
            json!({"protocolVersion":VERSION,"capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}})
        } else {
            let native = request.headers["mcp-session-id"].to_str().unwrap();
            assert_eq!(request.headers["mcp-protocol-version"], VERSION);
            let session = sessions.get_mut(native).unwrap();
            assert_eq!(session.0, account, "native session crossed credential accounts");
            if message["method"] == "notifications/initialized" {
                assert!(!session.1); session.1 = true;
                let mut reply = Reply::body(""); reply.status = 202; return reply;
            }
            assert!(session.1);
            if message["method"] == "notifications/cancelled" {
                assert!(message["params"]["requestId"].as_u64().is_some_and(|id| id > 0));
                assert!(message["params"].get("reason").is_none());
                let mut reply = Reply::body(""); reply.status = 202; return reply;
            }
            assert_ne!(message["id"], "agent-call");
            match message["method"].as_str().unwrap() {
                "tools/list" => json!({"tools":tools().iter().map(Tool::definition).collect::<Vec<_>>()}),
                "tools/call" => {
                    if message["params"]["arguments"]["text"] == "drop" {
                        let mut reply = Reply::body(""); reply.disconnect = true; return reply;
                    }
                    json!({"content":[{"type":"text","text":format!("{account}:{} {key} {native}", message["params"]["arguments"]["text"].as_str().unwrap())}]})
                }
                _ => panic!("unsupported fixture operation"),
            }
        };
        let result = json!({"jsonrpc":"2.0","id":message["id"],"result":result});
        let ping = json!({"jsonrpc":"2.0","id":"private-server-ping","method":"ping"});
        let mut reply = Reply::body(if sse { format!("data: {ping}\n\ndata: {result}\n\n") } else { result.to_string() });
        reply.headers.push(("content-type".into(), if sse {"text/event-stream"} else {"application/json"}.into()));
        if let Some(native) = created { reply.headers.push(("mcp-session-id".into(), native)); }
        let body = reply.chunks.pop().unwrap();
        reply.chunks = body.chunks(13).map(Bytes::copy_from_slice).collect();
        if message["params"]["arguments"]["text"] == "wait" {
            reply.delay = Duration::from_secs(1);
        }
        reply
    }).await;
    let store = SqliteStore::open(
        Arc::new(aap_config::PrivateDir::open(&fixture.root.join("s"), false).unwrap()),
        SecretBytes::new(vec![17; 32]).unwrap(),
        OpenMode::Existing,
        tokio::runtime::Handle::current(),
    )
    .await
    .unwrap();
    store
        .put(
            &ItemRef::new("private-second-ref".into()).unwrap(),
            [(
                Field::ApiKey,
                SecretBytes::new(b"synthetic-second-key".to_vec()).unwrap(),
            )]
            .into(),
            None,
        )
        .await
        .unwrap();
    drop(store);
    fixture.config.upstream_roots_der_base64 =
        vec![STANDARD.encode(fixture.origin.certificate.as_ref())];
    fixture.config.observation.max_events = 4096;
    let profile = &mut fixture.config.profiles[0];
    profile.id = "mcp-first".into();
    profile.origin = fixture.origin.origin();
    profile.addresses = AddressPolicy::Pinned(vec![fixture.origin.address.ip()]);
    profile.routes = ["POST", "DELETE"]
        .into_iter()
        .map(|method| Route {
            method: method.into(),
            path: "/mcp".into(),
            query: None,
            max_request_bytes: 256 * 1024,
            max_response_bytes: 256 * 1024,
            allowed_headers: vec!["content-type".into(), "mcp-protocol-version".into()],
            streaming: false,
            require_approval: false,
        })
        .collect();
    profile.auth = Authentication::Mcp {
        item_id: "key".into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        tools: tools(),
    };
    let mut second = profile.clone();
    second.id = "mcp-second".into();
    if let Authentication::Mcp { item_id, .. } = &mut second.auth {
        *item_id = "second".into();
    }
    fixture.config.profiles.push(second);
    fixture.catalog.items[0].profile = "mcp-first".into();
    let mut item = fixture.catalog.items[0].clone();
    item.item_id = "second".into();
    item.profile = "mcp-second".into();
    item.account_alias = "second".into();
    item.credential.key = "private-second-ref".into();
    fixture.catalog.items.push(item);
    fixture.write();
    fixture
}
async fn attachment(
    fixture: &Fixture,
    ready: &Ready,
    resources: &[&str],
) -> (PathBuf, DaemonSessionClient) {
    let (status, attachment) = local(
        fixture.root.join("r").join(&ready.control_socket),
        "/aap/operator/v1/session/create",
        json!({"resources":resources,"lifetime_seconds":60}),
    )
    .await;
    assert!(status.is_success());
    let socket = fixture
        .root
        .join("r")
        .join(attachment["ingress_socket"].as_str().unwrap());
    (socket.clone(), DaemonSessionClient::new(socket))
}
async fn observation(fixture: &Fixture, ready: &Ready, expect_children: bool) {
    let mut cursor = None;
    let mut children = false;
    let mut count = 0;
    loop {
        let (status, batch) = local(
            fixture.root.join("r").join(&ready.observation_socket),
            "/aap/observe/v1/read",
            json!({"cursor":cursor,"limit":256}),
        )
        .await;
        assert!(status.is_success());
        safe(&serde_json::to_vec(&batch).unwrap());
        let batch: aap_observe::Batch = serde_json::from_value(batch).unwrap();
        assert!(batch.gap.is_none(), "fixture observation must be complete");
        if batch.records.is_empty() {
            break;
        }
        count += batch.records.len();
        assert!(count < 4096);
        for record in &batch.records {
            children |= record.event.parent_request_id.is_some();
            if let aap_observe::Data::ContentChunk { body_base64, .. } = &record.event.data {
                safe(&STANDARD.decode(body_base64).unwrap());
            }
        }
        cursor = Some(batch.cursor);
    }
    assert!(count > 0);
    assert_eq!(children, expect_children);
}

#[tokio::test]
async fn remote_mcp_daemon_and_stdio_bridge_keep_accounts_and_sessions_private() {
    for sse in [false, true] {
        let fixture = fixture(sse).await;
        let (mut child, ready) = fixture.start().await;
        let (_, first) = attachment(&fixture, &ready, &["mcp-first"]).await;
        let (_, same_account) = attachment(&fixture, &ready, &["mcp-first"]).await;
        let (_, other_account) = attachment(&fixture, &ready, &["mcp-second"]).await;
        assert!(
            first
                .execute(input(&fixture, "mcp-first", call("early")))
                .await
                .is_err()
        );
        assert!(
            first
                .execute(input(&fixture, "mcp-second", initialize()))
                .await
                .is_err()
        );
        assert!(fixture.origin.requests.lock().unwrap().is_empty());
        for (client, resource, account) in [
            (&first, "mcp-first", "first"),
            (&same_account, "mcp-first", "first"),
            (&other_account, "mcp-second", "second"),
        ] {
            handshake(&fixture, client, resource).await;
            let list = response(
                client
                    .execute(input(
                        &fixture,
                        resource,
                        json!({"jsonrpc":"2.0","id":"list","method":"tools/list"}),
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                list["result"]["tools"],
                json!(tools().iter().map(Tool::definition).collect::<Vec<_>>())
            );
            let before = fixture.origin.requests.lock().unwrap().len();
            for message in [
                json!({"jsonrpc":"2.0","id":"bad-tool","method":"tools/call","params":{"name":"not-enrolled","arguments":{}}}),
                json!({"jsonrpc":"2.0","id":"bad-args","method":"tools/call","params":{"name":"echo","arguments":{"text":42}}}),
                json!({"jsonrpc":"2.0","id":"bad-method","method":"sampling/createMessage","params":{}}),
            ] {
                assert!(
                    client
                        .execute(input(&fixture, resource, message))
                        .await
                        .is_err()
                );
            }
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), before);
            let request = input(&fixture, resource, call("hello"));
            let value = response(client.execute(request.clone()).await.unwrap()).await;
            assert_eq!(value["id"], "agent-call");
            assert_eq!(
                value["result"]["content"][0]["text"],
                format!("{account}:hello [redacted] [redacted]")
            );
            let before = fixture.origin.requests.lock().unwrap().len();
            assert_eq!(
                client.execute(request.clone()).await.unwrap().headers()["x-aap-operation-state"],
                "existing"
            );
            assert_eq!(
                client
                    .request_status(request.request_id)
                    .await
                    .unwrap()
                    .state,
                OperationState::Completed
            );
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), before);
        }
        let closed = first.execute(delete(&fixture, "mcp-first")).await.unwrap();
        assert_eq!(closed.status(), 204);
        assert_eq!(closed.headers()["x-aap-remote-cleanup"], "confirmed");
        assert!(
            first
                .execute(input(&fixture, "mcp-first", call("closed")))
                .await
                .is_err()
        );
        response(
            same_account
                .execute(input(&fixture, "mcp-first", call("still-live")))
                .await
                .unwrap(),
        )
        .await;
        response(
            other_account
                .execute(input(&fixture, "mcp-second", call("still-live")))
                .await
                .unwrap(),
        )
        .await;
        let (socket, _) = attachment(&fixture, &ready, &["mcp-first"]).await;
        let mut bridge = McpPeer::start(socket).await;
        for message in [initialize(), initialized(), call("bridge")] {
            let result = bridge
                .call(
                    "request.execute",
                    serde_json::to_value(input(&fixture, "mcp-first", message)).unwrap(),
                )
                .await;
            assert_eq!(result["isError"], false);
            let content = &result["structuredContent"];
            let body = STANDARD
                .decode(content["body_base64"].as_str().unwrap())
                .unwrap();
            if content["status"] == 200 {
                decoded(&body);
            } else {
                assert_eq!(content["status"], 202);
                assert!(body.is_empty());
            }
        }
        let result = bridge
            .call(
                "request.execute",
                serde_json::to_value(delete(&fixture, "mcp-first")).unwrap(),
            )
            .await;
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["status"], 204);
        assert!(
            result["structuredContent"]["headers"]
                .as_array()
                .unwrap()
                .contains(&json!(["x-aap-remote-cleanup", "confirmed"]))
        );
        bridge.close().await;
        let natives = fixture
            .origin
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter_map(|request| {
                request
                    .headers
                    .get("mcp-session-id")
                    .map(|value| value.to_str().unwrap().to_owned())
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            natives.len(),
            4,
            "local sessions must not share native authority"
        );
        observation(&fixture, &ready, true).await;
        stop(&mut child).await;
    }
}

#[tokio::test]
async fn remote_mcp_connect_uses_the_same_context_and_denies_ambiguous_accounts() {
    let mut fixture = fixture(true).await;
    let root = interception::enroll_ca(&mut fixture).await;
    let (mut child, ready) = fixture.start().await;
    let (socket, client) = attachment(&fixture, &ready, &["mcp-first"]).await;
    let authority = format!("fixture.test:{}", fixture.origin.address.port());
    for message in [initialize(), initialized(), call("tunnel")] {
        let request = interception::http_request(
            "POST",
            "/mcp",
            &authority,
            "application/json",
            Bytes::from(serde_json::to_vec(&message).unwrap()),
        );
        let (status, headers, body) =
            interception::request(&socket, &authority, root.clone(), request).await;
        assert!(!headers.contains_key("mcp-session-id"));
        if message["method"] == "notifications/initialized" {
            assert_eq!(status, 202);
            assert!(body.is_empty());
        } else {
            assert_eq!(status, 200);
            assert_eq!(decoded(&body)["id"], message["id"]);
        }
    }
    response(
        client
            .execute(input(&fixture, "mcp-first", call("same-context")))
            .await
            .unwrap(),
    )
    .await;
    let before = fixture.origin.requests.lock().unwrap().len();
    for header in ["mcp-session-id", "mcp-protocol-version"] {
        let mut request = interception::http_request(
            "POST",
            "/mcp",
            &authority,
            "application/json",
            Bytes::from(call("forbidden").to_string()),
        );
        request
            .headers_mut()
            .insert(header, http::HeaderValue::from_static("attacker-selected"));
        let (status, headers, body) =
            interception::request(&socket, &authority, root.clone(), request).await;
        assert!(!status.is_success());
        assert_eq!(headers["x-aap-error"], "1");
        let error: aap_types::Error = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            error.code,
            if header == "mcp-session-id" {
                ErrorCode::PolicyDenied
            } else {
                ErrorCode::InspectionUnavailable
            }
        );
    }
    let (ambiguous, _) = attachment(&fixture, &ready, &["mcp-first", "mcp-second"]).await;
    let request = interception::http_request(
        "POST",
        "/mcp",
        &authority,
        "application/json",
        Bytes::from(initialize().to_string()),
    );
    let (status, _, _) = interception::request(&ambiguous, &authority, root.clone(), request).await;
    assert!(status.is_client_error());
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), before);
    let request = interception::http_request(
        "DELETE",
        "/mcp",
        &authority,
        "application/json",
        Bytes::new(),
    );
    let (status, headers, body) = interception::request(&socket, &authority, root, request).await;
    assert_eq!(status, 204);
    assert_eq!(headers["x-aap-remote-cleanup"], "confirmed");
    assert!(body.is_empty());
    assert!(
        client
            .execute(input(&fixture, "mcp-first", call("closed")))
            .await
            .is_err()
    );
    observation(&fixture, &ready, true).await;
    stop(&mut child).await;
}

#[tokio::test]
async fn remote_mcp_daemon_disconnect_is_uncertain_and_never_replayed() {
    let fixture = fixture(false).await;
    let (mut child, ready) = fixture.start().await;
    let (_, client) = attachment(&fixture, &ready, &["mcp-first"]).await;
    handshake(&fixture, &client, "mcp-first").await;
    let request = input(&fixture, "mcp-first", call("drop"));
    assert!(client.execute(request.clone()).await.is_err());
    assert_eq!(
        client
            .request_status(request.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::OutcomeUnknown
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    let existing = client.execute(request).await.unwrap();
    assert_eq!(existing.headers()["x-aap-operation-state"], "existing");
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    // An explicit, separately authorized new action is not a retry. A dropped
    // ordinary request retires its mapping, not an otherwise valid session.
    response(
        client
            .execute(input(&fixture, "mcp-first", call("different-action")))
            .await
            .unwrap(),
    )
    .await;
    let closed = client.execute(delete(&fixture, "mcp-first")).await.unwrap();
    assert_eq!(closed.headers()["x-aap-remote-cleanup"], "confirmed");
    handshake(&fixture, &client, "mcp-first").await;
    response(
        client
            .execute(input(&fixture, "mcp-first", call("fresh")))
            .await
            .unwrap(),
    )
    .await;
    {
        let requests = fixture.origin.requests.lock().unwrap();
        assert_eq!(requests.len(), 8);
        assert_eq!(
            requests
                .iter()
                .filter(|request| serde_json::from_slice::<Value>(&request.body)
                    .is_ok_and(|message| message["params"]["arguments"]["text"] == "drop"))
                .count(),
            1
        );
    }
    observation(&fixture, &ready, true).await;
    stop(&mut child).await;
}

#[tokio::test]
async fn remote_mcp_daemon_cancellation_stops_delivery_and_owns_one_child() {
    let fixture = fixture(false).await;
    let (mut child, ready) = fixture.start().await;
    let (_, client) = attachment(&fixture, &ready, &["mcp-first"]).await;
    handshake(&fixture, &client, "mcp-first").await;
    let input = input(&fixture, "mcp-first", call("wait"));
    let operation = input.request_id.clone();
    let mut pending = tokio::spawn({
        let client = client.clone();
        async move { client.execute(input).await }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if fixture.origin.requests.lock().unwrap().len() == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        client.cancel(operation.clone()).await.unwrap().state,
        OperationState::OutcomeUnknown
    );
    let result = tokio::time::timeout(Duration::from_secs(1), &mut pending).await;
    pending.abort();
    assert!(
        result
            .expect("cancellation must stop the waiting request")
            .unwrap()
            .is_err()
    );
    assert_eq!(
        client.cancel(operation.clone()).await.unwrap().state,
        OperationState::OutcomeUnknown
    );
    assert_eq!(
        client.request_status(operation).await.unwrap().state,
        OperationState::OutcomeUnknown
    );
    {
        let requests = fixture.origin.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            4,
            "repeat cancellation cannot send another notification"
        );
        let original: Value = serde_json::from_slice(&requests[2].body).unwrap();
        let notification: Value = serde_json::from_slice(&requests[3].body).unwrap();
        assert_eq!(notification["method"], "notifications/cancelled");
        assert_eq!(notification["params"]["requestId"], original["id"]);
        assert_ne!(original["id"], "agent-call");
        assert_eq!(
            requests[2].headers["mcp-session-id"],
            requests[3].headers["mcp-session-id"]
        );
    }
    observation(&fixture, &ready, true).await;
    stop(&mut child).await;
}
