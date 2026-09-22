use super::*;
use aap_types::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::json;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const CONTEXT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Default)]
struct Fixture {
    calls: Mutex<Vec<String>>,
    requests: Mutex<Vec<ExecuteRequest>>,
    response: Mutex<Vec<u8>>,
    existing: bool,
    wait: bool,
    started: tokio::sync::Notify,
    dropped: AtomicUsize,
}
impl Fixture {
    fn record(&self, name: &str) {
        self.calls.lock().unwrap().push(name.into());
    }
    fn status(&self, request_id: String) -> OperationStatus {
        OperationStatus {
            request_id,
            state: OperationState::PendingApproval,
            status: None,
        }
    }
}
impl AgentService for Fixture {
    fn execute(&self, request: ExecuteRequest) -> BoxFuture<'_, aap_types::Result<Response>> {
        Box::pin(async move {
            self.record("execute");
            self.started.notify_one();
            if self.wait {
                struct OnDrop<'a>(&'a AtomicUsize);
                impl Drop for OnDrop<'_> {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, Ordering::SeqCst);
                    }
                }
                let _on_drop = OnDrop(&self.dropped);
                std::future::pending::<()>().await;
            }
            let payload = if self.existing {
                serde_json::to_vec(&self.status(request.request_id.clone())).unwrap()
            } else {
                self.response.lock().unwrap().clone()
            };
            self.requests.lock().unwrap().push(request);
            let mut response = http::Response::builder()
                .status(401)
                .header("content-type", "application/json");
            if self.existing {
                response = response
                    .status(202)
                    .header("x-aap-operation-state", "existing");
            }
            Ok(response
                .body(
                    Full::new(Bytes::from(payload))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap())
        })
    }
    fn search_items(&self, _: SearchItems) -> BoxFuture<'_, aap_types::Result<SearchResult>> {
        Box::pin(async {
            self.record("search");
            Ok(SearchResult {
                items: vec![],
                next_cursor: None,
            })
        })
    }
    fn get_login(&self, _: GetLogin) -> BoxFuture<'_, aap_types::Result<Login>> {
        Box::pin(async {
            self.record("login");
            Err(ErrorCode::VaultLocked.into())
        })
    }
    fn auth_status(&self, _: AuthContext) -> BoxFuture<'_, aap_types::Result<AuthStatus>> {
        Box::pin(async {
            self.record("auth_status");
            Ok(AuthStatus {
                item_id: "item".into(),
                account_alias: "work".into(),
                state: AuthState::Unauthenticated,
            })
        })
    }
    fn logout(&self, _: AuthContext) -> BoxFuture<'_, aap_types::Result<Logout>> {
        Box::pin(async {
            self.record("logout");
            Ok(Logout {
                state: AuthState::Revoked,
                remote_logout: RemoteLogout::NotSupported,
            })
        })
    }
    fn request_status(&self, id: String) -> BoxFuture<'_, aap_types::Result<OperationStatus>> {
        Box::pin(async {
            self.record("status");
            Ok(self.status(id))
        })
    }
    fn cancel(&self, id: String) -> BoxFuture<'_, aap_types::Result<OperationStatus>> {
        Box::pin(async {
            self.record("cancel");
            Ok(self.status(id))
        })
    }
    fn admit_connect(&self, _: String) -> BoxFuture<'_, aap_types::Result<()>> {
        Box::pin(async { panic!("MCP tools must not open an independent connector") })
    }
}
fn request() -> Value {
    json!({"request_id":ID,"resource":"site","method":"POST","target":"https://fixture.test/session","headers":[["content-type","application/json"]],"body_base64":STANDARD.encode([0, 255, 10])})
}
fn payload(result: CallToolResult) -> Value {
    let wire = serde_json::to_value(&result).unwrap();
    assert!(
        wire.get("resultType").is_none(),
        "newer SDK wire fields escaped the pinned protocol"
    );
    let structured = result.structured_content.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(wire["content"][0]["text"].as_str().unwrap()).unwrap(),
        structured
    );
    structured
}

#[tokio::test]
async fn seven_strict_tools_share_the_session_service() {
    let definitions = Tools::definitions();
    assert_eq!(
        definitions.len(),
        7,
        "all planned local tools must be exposed"
    );
    for definition in definitions {
        assert_eq!(definition.input_schema["type"], "object");
        assert_eq!(definition.input_schema["additionalProperties"], false);
        assert!(definition.input_schema["required"].is_array());
    }
    let service = Arc::new(Fixture::default());
    let tools = Tools::new(service.clone());
    assert_eq!(
        payload(
            tools
                .call(
                    "vault.search_items",
                    json!({"uri":"https://fixture.test/login"})
                )
                .await
                .unwrap()
        )["items"],
        json!([])
    );
    let failure = tools
        .call(
            "vault.get_login",
            json!({"request_id":ID,"item_id":"item","uri":"https://fixture.test/login"}),
        )
        .await
        .unwrap();
    assert_eq!(failure.is_error, Some(true));
    assert_eq!(payload(failure)["code"], "vault_locked");
    assert_eq!(
        payload(
            tools
                .call("vault.auth_status", json!({"auth_context":CONTEXT}))
                .await
                .unwrap()
        )["state"],
        "unauthenticated"
    );
    assert_eq!(
        payload(
            tools
                .call("vault.logout", json!({"auth_context":CONTEXT}))
                .await
                .unwrap()
        )["state"],
        "revoked"
    );
    for name in ["request.status", "request.cancel"] {
        assert_eq!(
            payload(tools.call(name, json!({"request_id":ID})).await.unwrap())["state"],
            "pending_approval"
        );
    }
    let result = tools.call("request.execute", request()).await.unwrap();
    assert_eq!(
        result.is_error,
        Some(false),
        "resource HTTP errors are not MCP protocol errors"
    );
    assert_eq!(payload(result)["status"], 401);
    assert_eq!(
        *service.calls.lock().unwrap(),
        [
            "search",
            "login",
            "auth_status",
            "logout",
            "status",
            "cancel",
            "execute"
        ]
    );
    assert!(tools.call("vault.reveal", json!({})).await.is_err());
}

#[tokio::test]
async fn invalid_and_over_limit_arguments_never_reach_the_service() {
    let service = Arc::new(Fixture::default());
    let tools = Tools::new(service.clone());
    for (name, arguments) in [
        (
            "vault.search_items",
            json!({"uri":"https://fixture.test", "store_ref":"private"}),
        ),
        ("request.cancel", json!({"request_id":ID,"approve":true})),
        (
            "vault.get_login",
            json!({"request_id":"bad","item_id":"item","uri":"https://fixture.test"}),
        ),
        ("vault.auth_status", json!({"auth_context":"bad"})),
    ] {
        let result = tools.call(name, arguments).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        assert_eq!(payload(result)["code"], "request_invalid");
    }
    for body in [
        "?".into(),
        "Zg".into(),
        STANDARD.encode(vec![0; MAX_BODY + 1]),
    ] {
        let mut arguments = request();
        arguments["body_base64"] = json!(body);
        assert_eq!(
            tools
                .call("request.execute", arguments)
                .await
                .unwrap()
                .is_error,
            Some(true)
        );
    }
    assert!(service.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn binary_responses_and_existing_operation_state_are_unambiguous() {
    let service = Arc::new(Fixture::default());
    *service.response.lock().unwrap() = vec![255, 0, 10];
    let result = payload(
        Tools::new(service.clone())
            .call("request.execute", request())
            .await
            .unwrap(),
    );
    assert_eq!(result["kind"], "response");
    assert_eq!(result["complete"], true);
    assert_eq!(
        STANDARD
            .decode(result["body_base64"].as_str().unwrap())
            .unwrap(),
        [255, 0, 10]
    );
    assert_eq!(
        STANDARD
            .decode(&service.requests.lock().unwrap()[0].body_base64)
            .unwrap(),
        [0, 255, 10]
    );
    *service.response.lock().unwrap() =
        serde_json::to_vec(&json!({"kind":"operation","state":"completed"})).unwrap();
    assert_eq!(
        payload(
            Tools::new(service)
                .call("request.execute", request())
                .await
                .unwrap()
        )["kind"],
        "response"
    );
    let service = Arc::new(Fixture {
        existing: true,
        ..Default::default()
    });
    let result = payload(
        Tools::new(service)
            .call("request.execute", request())
            .await
            .unwrap(),
    );
    assert_eq!(result["kind"], "operation");
    assert_eq!(result["operation"]["state"], "pending_approval");
    assert!(result.get("headers").is_none());
}

#[tokio::test]
async fn oversized_response_is_not_returned_as_successful_truncation() {
    let service = Arc::new(Fixture::default());
    *service.response.lock().unwrap() = vec![0; MAX_BODY + 1];
    let result = Tools::new(service.clone())
        .call("request.execute", request())
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    let result = payload(result);
    assert_eq!(result["code"], "limit_exceeded");
    assert_eq!(result["request_id"], ID);
    assert_eq!(
        service.requests.lock().unwrap().len(),
        1,
        "response failure must never retry a request"
    );
}

struct Wire {
    input: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    output: BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    task: tokio::task::JoinHandle<aap_types::Result<()>>,
}
impl Wire {
    fn new(service: Arc<Fixture>) -> Self {
        let (client, server) = tokio::io::duplex(8192);
        let (read, write) = tokio::io::split(client);
        let (input, output) = tokio::io::split(server);
        let task = tokio::spawn(serve(input, output, Tools::new(service)));
        Self {
            input: write,
            output: BufReader::new(read),
            task,
        }
    }
    async fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        self.input.write_all(&bytes).await.unwrap();
    }
    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.output.read_line(&mut line),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(count > 0, "MCP server closed before responding");
        serde_json::from_str(&line).unwrap()
    }
    async fn initialize(&mut self) {
        self.send(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2099-01-01","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})).await;
        let result = self.receive().await;
        assert_eq!(result["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["result"]["capabilities"], json!({"tools":{}}));
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
    }
    async fn call(&mut self, id: u64, name: &str, arguments: Value) {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await;
    }
    async fn close(mut self) {
        self.input.shutdown().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn stdio_negotiates_and_translates_real_json_rpc_frames() {
    let service = Arc::new(Fixture::default());
    let mut wire = Wire::new(service.clone());
    wire.call(
        4,
        "vault.search_items",
        json!({"uri":"https://fixture.test"}),
    )
    .await;
    assert!(wire.receive().await.get("error").is_some());
    assert!(service.calls.lock().unwrap().is_empty());
    wire.initialize().await;
    wire.send(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .await;
    assert_eq!(
        wire.receive().await["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    wire.call(2, "request.execute", request()).await;
    let response = wire.receive().await;
    assert_eq!(response["id"], 2);
    assert_eq!(response["result"]["structuredContent"]["kind"], "response");
    assert!(response["result"].get("resultType").is_none());
    wire.close().await;
}

#[tokio::test]
async fn stdio_rejects_duplicate_members_and_oversized_unterminated_frames() {
    let service = Arc::new(Fixture::default());
    let mut wire = Wire::new(service.clone());
    wire.initialize().await;
    wire.input.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"vault.search_items\",\"arguments\":{\"uri\":\"safe\",\"uri\":\"unsafe\"}}}\n").await.unwrap();
    assert_eq!(wire.receive().await["error"]["code"], -32700);
    assert!(service.calls.lock().unwrap().is_empty());
    let _ = wire.input.write_all(&vec![b' '; MAX_INPUT + 1]).await;
    let error = tokio::time::timeout(std::time::Duration::from_secs(3), &mut wire.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitExceeded);
}

#[tokio::test]
async fn stdio_pending_work_does_not_block_status_or_connection_scoped_cancellation() {
    let service = Arc::new(Fixture {
        wait: true,
        ..Default::default()
    });
    let mut wire = Wire::new(service.clone());
    wire.initialize().await;
    wire.call(1, "request.execute", request()).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        service.started.notified(),
    )
    .await
    .unwrap();
    wire.call(2, "request.status", json!({"request_id":ID}))
        .await;
    let result = wire.receive().await;
    assert_eq!(result["id"], 2);
    assert_eq!(
        result["result"]["structuredContent"]["state"],
        "pending_approval"
    );
    // Cancelling a completed status query must not touch the original call.
    wire.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}))
        .await;
    wire.call(3, "request.status", json!({"request_id":ID}))
        .await;
    assert_eq!(wire.receive().await["id"], 3);
    assert_eq!(service.dropped.load(Ordering::SeqCst), 0);
    wire.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"private reason is not logged"}})).await;
    wire.call(4, "request.cancel", json!({"request_id":ID}))
        .await;
    assert_eq!(wire.receive().await["id"], 4);
    assert_eq!(service.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        service
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|name| *name == "cancel")
            .count(),
        1,
        "notifications must not turn a JSON-RPC ID into unrelated operation cancellation"
    );
    wire.close().await;
}

#[tokio::test]
async fn stdio_reserves_status_capacity_and_reclaims_cancelled_work() {
    let service = Arc::new(Fixture {
        wait: true,
        ..Default::default()
    });
    let mut wire = Wire::new(service.clone());
    wire.initialize().await;
    // Each work call reserves a worst-case response before it can allocate one.
    for id in 1..=3 {
        wire.call(id, "request.execute", request()).await;
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            service.started.notified(),
        )
        .await
        .unwrap();
    }
    wire.call(4, "request.execute", request()).await;
    assert_eq!(
        wire.receive().await["result"]["structuredContent"]["code"],
        "limit_exceeded"
    );
    wire.call(5, "request.status", json!({"request_id":ID}))
        .await;
    assert_eq!(
        wire.receive().await["result"]["structuredContent"]["state"],
        "pending_approval"
    );
    wire.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}))
        .await;
    wire.call(6, "request.status", json!({"request_id":ID}))
        .await;
    assert_eq!(wire.receive().await["id"], 6);
    assert_eq!(service.dropped.load(Ordering::SeqCst), 1);
    wire.call(7, "request.execute", request()).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        service.started.notified(),
    )
    .await
    .unwrap();
    wire.close().await;
    assert_eq!(
        service.dropped.load(Ordering::SeqCst),
        4,
        "EOF left an owned request running"
    );
}

#[tokio::test]
async fn stdio_concurrent_duplicate_rpc_ids_fail_without_reassigning_authority() {
    let service = Arc::new(Fixture {
        wait: true,
        ..Default::default()
    });
    let mut wire = Wire::new(service.clone());
    wire.initialize().await;
    wire.call(1, "request.execute", request()).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        service.started.notified(),
    )
    .await
    .unwrap();
    wire.call(1, "request.cancel", json!({"request_id":ID}))
        .await;
    assert_eq!(wire.receive().await["error"]["code"], -32600);
    assert_eq!(
        (&mut wire.task).await.unwrap().unwrap_err().code,
        ErrorCode::RequestConflict
    );
    assert_eq!(service.dropped.load(Ordering::SeqCst), 1);
    assert!(
        !service
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|name| name == "cancel")
    );
}

#[tokio::test(start_paused = true)]
async fn stdio_bounds_initialization_partial_frames_and_stalled_output() {
    let service = Arc::new(Fixture::default());
    let mut uninitialized = Wire::new(service.clone());
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    assert_eq!(
        (&mut uninitialized.task).await.unwrap().unwrap_err().code,
        ErrorCode::LimitExceeded
    );
    let mut partial = Wire::new(service.clone());
    partial.initialize().await;
    partial.input.write_all(b"{").await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    assert_eq!(
        (&mut partial.task).await.unwrap().unwrap_err().code,
        ErrorCode::LimitExceeded
    );
    *service.response.lock().unwrap() = vec![0; MAX_BODY];
    let mut stalled = Wire::new(service.clone());
    stalled.initialize().await;
    stalled.call(1, "request.execute", request()).await;
    service.started.notified().await;
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    assert_eq!(
        (&mut stalled.task).await.unwrap().unwrap_err().code,
        ErrorCode::LimitExceeded
    );
}
