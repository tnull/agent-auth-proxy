use super::*;
use aap_client::DaemonSessionClient;
use aap_types::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{os::unix::fs::DirBuilderExt, path::PathBuf, time::Duration};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::var_os("AAP_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = root.join(format!(
            "aap-http-{}",
            aap_types::ids::random_id(16).unwrap()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Echo {
    label: &'static str,
    calls: AtomicUsize,
    delay: Duration,
    interrupted: Arc<AtomicBool>,
    started: tokio::sync::Notify,
}
impl Echo {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            interrupted: Arc::new(AtomicBool::new(false)),
            started: tokio::sync::Notify::new(),
        }
    }
}
struct Interrupted(Arc<AtomicBool>, bool);
impl Drop for Interrupted {
    fn drop(&mut self) {
        if !self.1 {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}
impl AgentService for Echo {
    fn open_stream(
        &self,
        _request: aap_types::stream::Open,
    ) -> BoxFuture<'_, Result<aap_types::stream::service::Admission>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ErrorCode::PolicyDenied.into())
        })
    }
    fn execute(&self, _request: ExecuteRequest) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut interrupted = Interrupted(self.interrupted.clone(), false);
            self.started.notify_one();
            tokio::time::sleep(self.delay).await;
            interrupted.1 = true;
            Ok(http::Response::new(
                Full::new(Bytes::from_static(self.label.as_bytes()))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            ))
        })
    }
    fn search_items(&self, _request: SearchItems) -> BoxFuture<'_, Result<SearchResult>> {
        Box::pin(async { Err(ErrorCode::PolicyDenied.into()) })
    }
    fn get_login(&self, _request: GetLogin) -> BoxFuture<'_, Result<Login>> {
        Box::pin(async { Err(ErrorCode::PolicyDenied.into()) })
    }
    fn auth_status(&self, _request: AuthContext) -> BoxFuture<'_, Result<AuthStatus>> {
        Box::pin(async { Err(ErrorCode::PolicyDenied.into()) })
    }
    fn logout(&self, _request: AuthContext) -> BoxFuture<'_, Result<Logout>> {
        Box::pin(async { Err(ErrorCode::PolicyDenied.into()) })
    }
    fn request_status(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>> {
        Box::pin(async move {
            Ok(OperationStatus {
                request_id,
                state: OperationState::Completed,
                status: Some(200),
            })
        })
    }
    fn cancel(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>> {
        Box::pin(async move {
            Ok(OperationStatus {
                request_id,
                state: OperationState::Cancelled,
                status: None,
            })
        })
    }
    fn admit_connect(&self, _authority: String) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(ErrorCode::PolicyDenied.into()) })
    }
}

#[tokio::test]
async fn expired_http_metadata_rejects_even_an_already_ready_body() {
    struct Reader;
    impl LocalHandler for Reader {
        fn handle(&self, mut request: http::Request<Incoming>) -> BoxFuture<'_, Response> {
            Box::pin(async move {
                let now = tokio::time::Instant::now();
                let deadline = if request.uri().path() == "/expired" {
                    now - Duration::from_secs(1)
                } else {
                    now + Duration::from_secs(10)
                };
                request
                    .extensions_mut()
                    .insert(crate::ingress::RequestDeadline(deadline));
                match read_body(request).await {
                    Ok(bytes) => {
                        assert!(bytes.is_empty());
                        json_response(&"accepted").unwrap()
                    }
                    Err(error) => error_response(error),
                }
            })
        }
    }
    let root = Directory::new();
    let directory = Arc::new(aap_config::PrivateDir::open(&root.0, false).unwrap());
    let binding = directory.bind_socket("ready-body.sock").unwrap();
    let shutdown = Cancellation::default();
    let server = tokio::spawn(serve_local(
        binding.listener().unwrap(),
        Arc::new(Reader),
        rustix::process::geteuid().as_raw(),
        shutdown.clone(),
    ));
    let path = root.0.join("ready-body.sock");
    assert!(
        raw(&path, "/live", b"", "")
            .await
            .starts_with("HTTP/1.1 200")
    );
    let expired = raw(&path, "/expired", b"", "").await;
    shutdown.cancel();
    server.await.unwrap().unwrap();
    assert!(
        expired.starts_with("HTTP/1.1 400"),
        "expired metadata accepted an already-ready body: {expired}"
    );
}

#[tokio::test]
async fn expired_stream_metadata_never_admits_a_ready_request() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut peer, mut local) = tokio::net::UnixStream::pair().unwrap();
    let operation = aap_types::stream::Open {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "raw".into(),
    };
    let body = serde_json::to_vec(&operation).unwrap();
    let header = format!(
        "POST /aap/v1/stream/open HTTP/1.1\r\nHost: aap.local\r\nConnection: upgrade\r\nUpgrade: aap-stream/1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    peer.write_all(header.as_bytes()).await.unwrap();
    peer.write_all(&body).await.unwrap();
    let prelude = crate::ingress::read_prelude(&mut local).await.unwrap();
    let service = Arc::new(Echo::new("must not admit"));
    crate::stream::opening::serve(local, prelude, service.clone(), tokio::time::Instant::now())
        .await
        .unwrap();
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        0,
        "expired ready metadata reached admission"
    );
    let mut response = String::new();
    peer.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 400 "));
}
fn request() -> ExecuteRequest {
    ExecuteRequest {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "fixture".into(),
        auth_context: None,
        method: "POST".into(),
        target: "https://fixture.test/messages".into(),
        headers: vec![],
        body_base64: String::new(),
    }
}

#[tokio::test]
async fn clients_reach_only_the_service_bound_to_their_private_socket() {
    let root = Directory::new();
    let directory = Arc::new(aap_config::PrivateDir::open(&root.0, false).unwrap());
    let one = directory.bind_socket("one.sock").unwrap();
    let two = directory.bind_socket("two.sock").unwrap();
    let shutdown = Cancellation::default();
    let uid = rustix::process::geteuid().as_raw();
    let first = tokio::spawn(serve_session(
        one.listener().unwrap(),
        Arc::new(Echo::new("one")),
        uid,
        shutdown.clone(),
    ));
    let second = tokio::spawn(serve_session(
        two.listener().unwrap(),
        Arc::new(Echo::new("two")),
        uid,
        shutdown.clone(),
    ));
    for (socket, expected) in [("one.sock", "one"), ("two.sock", "two")] {
        let client = DaemonSessionClient::new(root.0.join(socket));
        let response = tokio::time::timeout(Duration::from_secs(2), client.execute(request()))
            .await
            .unwrap()
            .expect("local client request failed");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
        let status = client
            .request_status(aap_types::ids::random_id(16).unwrap())
            .await
            .unwrap();
        assert_eq!(status.state, OperationState::Completed);
        assert!(
            matches!(client.search_items(SearchItems { uri: "https://fixture.test".into(), query: None, cursor: None }).await, Err(error) if error.code == ErrorCode::PolicyDenied)
        );
    }
    shutdown.cancel();
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
}

#[tokio::test]
async fn status_and_cancel_remain_usable_when_all_work_connections_are_busy() {
    let root = Directory::new();
    let directory = Arc::new(aap_config::PrivateDir::open(&root.0, false).unwrap());
    let socket = directory.bind_socket("control-capacity.sock").unwrap();
    let mut echo = Echo::new("unused");
    echo.delay = Duration::from_secs(600);
    let echo = Arc::new(echo);
    let shutdown = Cancellation::default();
    let server = tokio::spawn(serve_session(
        socket.listener().unwrap(),
        echo.clone(),
        rustix::process::geteuid().as_raw(),
        shutdown.clone(),
    ));
    let client = DaemonSessionClient::new(root.0.join("control-capacity.sock"));
    let mut work = Vec::new();
    for _ in 0..28 {
        let client = client.clone();
        work.push(tokio::spawn(async move { client.execute(request()).await }));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while echo.calls.load(Ordering::SeqCst) != 28 {
            echo.started.notified().await;
        }
    })
    .await
    .unwrap();
    let excess = tokio::time::timeout(Duration::from_secs(2), client.execute(request()))
        .await
        .expect("work admission consumed a reserved control slot");
    assert!(matches!(
        excess,
        Err(Error {
            code: ErrorCode::LimitExceeded,
            ..
        })
    ));
    let id = aap_types::ids::random_id(16).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), client.request_status(id.clone()))
            .await
            .unwrap()
            .unwrap()
            .state,
        OperationState::Completed
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), client.cancel(id))
            .await
            .unwrap()
            .unwrap()
            .state,
        OperationState::Cancelled
    );
    shutdown.cancel();
    server.await.unwrap().unwrap();
    for driver in work {
        assert!(driver.await.unwrap().is_err());
    }
}

async fn raw(path: &std::path::Path, target: &str, body: &[u8], extra: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let headers = format!(
        "POST {target} HTTP/1.1\r\nHost: aap.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut output = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        stream.take(64 * 1024).read_to_end(&mut output),
    )
    .await
    .unwrap()
    .unwrap();
    String::from_utf8(output).unwrap()
}

#[tokio::test]
async fn malformed_json_authority_headers_and_operator_paths_never_reach_the_service() {
    let root = Directory::new();
    let directory = Arc::new(aap_config::PrivateDir::open(&root.0, false).unwrap());
    let binding = directory.bind_socket("session.sock").unwrap();
    let shutdown = Cancellation::default();
    let service = Arc::new(Echo::new("executed"));
    let server = tokio::spawn(serve_session(
        binding.listener().unwrap(),
        service.clone(),
        rustix::process::geteuid().as_raw(),
        shutdown.clone(),
    ));
    let good = serde_json::to_vec(&request()).unwrap();
    let mut unknown: serde_json::Value = serde_json::from_slice(&good).unwrap();
    unknown["session_id"] = "other-session".into();
    for (path, body, extra) in [
        (
            aap_types::wire::EXECUTE,
            serde_json::to_vec(&unknown).unwrap(),
            "",
        ),
        (
            aap_types::wire::EXECUTE,
            br#"{"request_id":"a","request_id":"b"}"#.to_vec(),
            "",
        ),
        (
            aap_types::wire::EXECUTE,
            good.clone(),
            "X-Session-ID: other\r\n",
        ),
        ("/aap/operator/v1/session/create", good.clone(), ""),
        ("https://aap.local/aap/v1/request/execute", good.clone(), ""),
    ] {
        let response = raw(&root.0.join("session.sock"), path, &body, extra).await;
        assert!(response.starts_with("HTTP/1.1 400") || response.starts_with("HTTP/1.1 403"));
        assert!(!response.contains("executed"));
    }
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    assert!(
        raw(
            &root.0.join("session.sock"),
            aap_types::wire::EXECUTE,
            &good,
            ""
        )
        .await
        .contains("executed")
    );
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    shutdown.cancel();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_cancels_inflight_service_work_and_the_client_reports_uncertainty() {
    let root = Directory::new();
    let directory = Arc::new(aap_config::PrivateDir::open(&root.0, false).unwrap());
    let binding = directory.bind_socket("session.sock").unwrap();
    let shutdown = Cancellation::default();
    let mut service = Echo::new("must-not-complete");
    service.delay = Duration::from_secs(60);
    let service = Arc::new(service);
    let server = tokio::spawn(serve_session(
        binding.listener().unwrap(),
        service.clone(),
        rustix::process::geteuid().as_raw(),
        shutdown.clone(),
    ));
    let client = DaemonSessionClient::new(root.0.join("session.sock"));
    let running = tokio::spawn(async move { client.execute(request()).await });
    tokio::time::timeout(Duration::from_secs(2), service.started.notified())
        .await
        .unwrap();
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(service.interrupted.load(Ordering::SeqCst));
    assert!(
        matches!(running.await.unwrap(), Err(error) if error.code == ErrorCode::OutcomeUnknown)
    );
}
