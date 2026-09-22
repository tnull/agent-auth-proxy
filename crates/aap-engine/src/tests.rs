use super::*;
use aap_policy::{AddressPolicy, Authentication, CredentialRef, Item, ItemApproval, Route};
use aap_secrets::{Field, ItemRef, SecretBytes, SecretStoreAdmin};
use aap_store_sqlite::{OpenMode, SqliteStore};
use aap_test_support::{Origin, Reply};
use aap_transport::HttpsTransport;
use aap_types::profile::ProviderKind;
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{net::SocketAddr, path::PathBuf, sync::Mutex};

struct CountedStore {
    inner: Arc<SqliteStore>,
    resolutions: Arc<AtomicUsize>,
}
impl SecretStore for CountedStore {
    fn status(&self) -> BoxFuture<'_, aap_secrets::Result<aap_secrets::StoreStatus>> {
        self.inner.status()
    }
    fn metadata<'a>(
        &'a self,
        item: &'a ItemRef,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::ItemMetadata>> {
        self.inner.metadata(item)
    }
    fn resolve<'a>(
        &'a self,
        item: &'a ItemRef,
        lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::Snapshot>> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        self.inner.resolve(item, lease)
    }
    fn revalidate<'a>(
        &'a self,
        item: &'a ItemRef,
        lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<()>> {
        self.inner.revalidate(item, lease)
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::var_os("AAP_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = root.join(format!(
            "aap-engine-{}",
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
struct FixedResolver(SocketAddr);
impl Resolver for FixedResolver {
    fn resolve<'a>(&'a self, _host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            assert_eq!(port, self.0.port());
            Ok(vec![self.0])
        })
    }
}
struct CancelAtEnd(HttpsTransport);
impl Transport for CancelAtEnd {
    fn execute(
        &self,
        endpoint: aap_transport::Endpoint,
        request: http::Request<Bytes>,
        limits: aap_transport::Limits,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move {
            let response = self
                .0
                .execute(endpoint, request, limits, cancellation.clone())
                .await?;
            Ok(response.map(|body| CancellingBody { body, cancellation }.boxed_unsync()))
        })
    }
}
struct CancellingBody {
    body: aap_types::Body,
    cancellation: Cancellation,
}
impl http_body::Body for CancellingBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>>>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.body).poll_frame(context);
        if matches!(result, std::task::Poll::Ready(None)) {
            this.cancellation.cancel();
        }
        result
    }
}
struct Fixture {
    origin: Origin,
    store: Arc<SqliteStore>,
    resolutions: Arc<AtomicUsize>,
    recorder: Recorder,
    _directory: Directory,
}
impl Fixture {
    async fn new() -> Self {
        let mut reply = Reply::body(Bytes::from_static(b"data: synthetic-"));
        reply.chunks.push(Bytes::from_static(b"api-key\n\n"));
        reply.headers = vec![
            ("content-type".into(), "text/event-stream".into()),
            ("set-cookie".into(), "secret-cookie=never-visible".into()),
        ];
        let origin = Origin::spawn(reply).await;
        let directory = Directory::new();
        let store = Arc::new(
            SqliteStore::open(
                Arc::new(aap_config::PrivateDir::open(&directory.0, false).unwrap()),
                SecretBytes::new(vec![17; 32]).unwrap(),
                OpenMode::Create,
                tokio::runtime::Handle::current(),
            )
            .await
            .unwrap(),
        );
        store
            .put(
                &ItemRef::new("private-reference".into()).unwrap(),
                [(
                    Field::ApiKey,
                    SecretBytes::new(b"synthetic-api-key".to_vec()).unwrap(),
                )]
                .into(),
                None,
            )
            .await
            .unwrap();
        Self {
            origin,
            store,
            resolutions: Arc::new(AtomicUsize::new(0)),
            recorder: Recorder::new(aap_types::ids::random_id(16).unwrap(), 256, 1024 * 1024)
                .unwrap(),
            _directory: directory,
        }
    }
    fn configuration(&self) -> Configuration {
        Configuration {
            catalog: Catalog {
                schema_version: 1,
                configuration_revision: 1,
                items: vec![Item {
                    item_id: "provider-key".into(),
                    label: "Fixture".into(),
                    account_alias: "test".into(),
                    profile: "provider".into(),
                    credential: CredentialRef {
                        store: "default".into(),
                        key: "private-reference".into(),
                    },
                    approval: ItemApproval::Inherit,
                }],
            },
            profiles: vec![ResourceProfile {
                id: "provider".into(),
                origin: self.origin.origin(),
                addresses: AddressPolicy::Pinned(vec![self.origin.address.ip()]),
                routes: vec![Route {
                    method: "POST".into(),
                    path: "/v1/chat/completions".into(),
                    query: None,
                    max_request_bytes: 1024 * 1024,
                    max_response_bytes: 1024 * 1024,
                    allowed_headers: vec!["content-type".into()],
                    streaming: true,
                    require_approval: false,
                }],
                auth: Authentication::ApiKey {
                    item_id: "provider-key".into(),
                    header: "authorization".into(),
                    prefix: "Bearer ".into(),
                    provider: ProviderKind::OpenAiChat,
                },
            }],
            stores: HashMap::from([(
                "default".into(),
                Arc::new(CountedStore {
                    inner: self.store.clone(),
                    resolutions: self.resolutions.clone(),
                }) as Arc<dyn SecretStore>,
            )]),
            resolver: Arc::new(FixedResolver(self.origin.address)),
            transport: Arc::new(HttpsTransport::new([self.origin.certificate.clone()]).unwrap()),
            inspector: Arc::new(aap_providers::TextOnly),
            approval: None,
            require_approval: false,
            recorder: self.recorder.clone(),
        }
    }
    fn request(&self) -> ExecuteRequest {
        ExecuteRequest { request_id: aap_types::ids::random_id(16).unwrap(), resource: "provider".into(), auth_context: None, method: "POST".into(), target: format!("{}/v1/chat/completions", self.origin.origin()),
            headers: vec![("content-type".into(), "application/json".into())], body_base64: base64::engine::general_purpose::STANDARD.encode(br#"{"model":"fixture","messages":[{"role":"user","content":"hello"}],"stream":true}"#) }
    }
}
fn options() -> SessionOptions {
    SessionOptions {
        resources: vec!["provider".into()],
        items: None,
        lifetime: Duration::from_secs(60),
        require_approval: false,
        require_observation: true,
    }
}

mod observation;
mod proxy;
mod vault;
mod website;

#[tokio::test]
async fn cancellation_at_eof_cannot_record_a_successful_completion() {
    let mut fixture = Fixture::new().await;
    let mut reply = Reply::body(Bytes::new());
    reply
        .headers
        .push(("content-type".into(), "text/plain".into()));
    fixture.origin = Origin::spawn(reply).await;
    let mut configuration = fixture.configuration();
    configuration.transport = Arc::new(CancelAtEnd(
        HttpsTransport::new([fixture.origin.certificate.clone()]).unwrap(),
    ));
    let broker = Broker::new(configuration).unwrap();
    let session = broker.create_session(options()).unwrap();
    let request = fixture.request();
    let response = session.execute(request.clone()).await.unwrap();
    assert!(
        response.into_body().collect().await.is_err(),
        "cancellation lost to EOF"
    );
    assert_eq!(
        session
            .request_status(request.request_id)
            .await
            .unwrap()
            .state,
        OperationState::OutcomeUnknown
    );
    assert!(
        fixture
            .recorder
            .read(None, 256)
            .unwrap()
            .records
            .iter()
            .all(|record| !matches!(
                (&record.event.direction, &record.event.data),
                (
                    aap_observe::Direction::Inbound,
                    aap_observe::Data::ContentEnd { complete: true, .. }
                )
            ))
    );
}

#[tokio::test]
async fn encrypted_store_to_real_tls_keeps_secrets_private_and_never_replays() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).expect("broker construction failed");
    let session = broker.create_session(options()).unwrap();
    let request = fixture.request();
    let response = session
        .execute(request.clone())
        .await
        .expect("brokered request failed");
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "data: [redacted]\n\n"
    );
    assert_eq!(
        session
            .request_status(request.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::Completed
    );
    let duplicate = session.execute(request.clone()).await.unwrap();
    drop(duplicate);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert_eq!(
        fixture.origin.requests.lock().unwrap()[0].headers["authorization"],
        "Bearer synthetic-api-key"
    );
    let mut changed = request.clone();
    changed.body_base64.push('A');
    assert!(
        matches!(session.execute(changed).await, Err(error) if error.code == ErrorCode::RequestConflict)
    );
    let other = broker.create_session(options()).unwrap();
    assert!(other.request_status(request.request_id).await.is_err());
    let observed = serde_json::to_string(&fixture.recorder.read(None, 256).unwrap()).unwrap();
    assert!(!observed.contains("private-reference"));
    assert!(!observed.contains("synthetic-api-key"));
    assert!(!observed.contains("never-visible"));
    let decoded: Vec<u8> = fixture
        .recorder
        .read(None, 256)
        .unwrap()
        .records
        .into_iter()
        .flat_map(|record| match record.event.data {
            aap_observe::Data::ContentChunk { body_base64, .. } => {
                base64::engine::general_purpose::STANDARD
                    .decode(body_base64)
                    .unwrap()
            }
            _ => vec![],
        })
        .collect();
    assert!(!String::from_utf8_lossy(&decoded).contains("synthetic-api-key"));
}

#[tokio::test]
async fn admission_approval_and_required_recording_fail_before_dispatch() {
    let fixture = Fixture::new().await;
    let mut configuration = fixture.configuration();
    configuration.require_approval = true;
    let broker = Broker::new(configuration).unwrap();
    let session = broker.create_session(options()).unwrap();
    assert!(
        matches!(session.execute(fixture.request()).await, Err(error) if error.code == ErrorCode::InteractionUnavailable)
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    let broker = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    let mut request = fixture.request();
    request.target = "https://unadmitted.test/v1/chat/completions".into();
    assert!(session.execute(request).await.is_err());
    let mut request = fixture.request();
    request.body_base64 = base64::engine::general_purpose::STANDARD
        .encode(br#"{"model":"fixture","messages":[],"tools":[{"type":"web_search"}]}"#);
    assert!(
        matches!(session.execute(request).await, Err(error) if error.code == ErrorCode::InspectionUnavailable)
    );
    fixture.recorder.set_available(false);
    assert!(
        matches!(session.execute(fixture.request()).await, Err(error) if error.code == ErrorCode::ObservationUnavailable)
    );
    assert_eq!(
        fixture.resolutions.load(Ordering::SeqCst),
        0,
        "offline required recording still resolved a secret"
    );
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
}

struct Gate {
    received: tokio::sync::mpsc::UnboundedSender<Arc<ApprovalRequest>>,
    decision: Mutex<Option<tokio::sync::oneshot::Receiver<bool>>>,
}
impl ApprovalProvider for Gate {
    fn approve(
        &self,
        request: Arc<ApprovalRequest>,
        _cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<bool>> {
        let decision = self.decision.lock().unwrap().take().unwrap();
        self.received.send(request).unwrap();
        Box::pin(async move {
            decision
                .await
                .map_err(|_| ErrorCode::InteractionUnavailable.into())
        })
    }
}
#[tokio::test]
async fn approval_is_async_and_revocation_invalidates_a_late_decision() {
    let fixture = Fixture::new().await;
    let (received_tx, mut received) = tokio::sync::mpsc::unbounded_channel();
    let (decision, decision_rx) = tokio::sync::oneshot::channel();
    let mut configuration = fixture.configuration();
    configuration.require_approval = true;
    configuration.approval = Some(Arc::new(Gate {
        received: received_tx,
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
    assert_eq!(
        session.request_status(request_id).await.unwrap().state,
        OperationState::PendingApproval
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    broker.revoke(&session).unwrap();
    let _ = decision.send(true);
    assert!(execution.await.unwrap().is_err());
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn supported_large_requests_are_redacted_incrementally() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    let mut request = fixture.request();
    request.body_base64 = STANDARD_FOR_TEST.encode(serde_json::to_vec(&serde_json::json!({"model":"fixture", "messages":[{"role":"user","content":"x".repeat(300*1024)}]})).unwrap());
    let response = session
        .execute(request)
        .await
        .expect("allowed bounded body rejected by redaction");
    response.into_body().collect().await.unwrap();
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
}
const STANDARD_FOR_TEST: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

struct PendingProvider(tokio::sync::mpsc::UnboundedSender<()>);
impl ApprovalProvider for PendingProvider {
    fn approve(
        &self,
        _request: Arc<ApprovalRequest>,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<bool>> {
        self.0.send(()).unwrap();
        Box::pin(async move {
            cancellation.cancelled().await;
            Ok(false)
        })
    }
}
#[tokio::test]
async fn pending_approval_payloads_have_a_shared_session_budget() {
    let fixture = Fixture::new().await;
    let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
    let mut configuration = fixture.configuration();
    configuration.require_approval = true;
    configuration.approval = Some(Arc::new(PendingProvider(sender)));
    let broker = Broker::new(configuration).unwrap();
    let session = broker.create_session(options()).unwrap();
    let mut request = fixture.request();
    request.body_base64 = STANDARD_FOR_TEST.encode(serde_json::to_vec(&serde_json::json!({"model":"fixture", "messages":[{"role":"user","content":"x".repeat(900*1024)}]})).unwrap());
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let mut next = request.clone();
        next.request_id = aap_types::ids::random_id(16).unwrap();
        let running = session.clone();
        tasks.push(tokio::spawn(async move { running.execute(next).await }));
        tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let result = tokio::time::timeout(Duration::from_secs(1), session.execute(request))
        .await
        .expect("pending payload budget did not reject overflow");
    assert!(matches!(result, Err(error) if error.code == ErrorCode::LimitExceeded));
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    broker.revoke(&session).unwrap();
    for task in tasks {
        assert!(task.await.unwrap().is_err());
    }
}

#[tokio::test]
async fn ambiguous_disconnect_and_abandoned_response_are_never_replayed() {
    for disconnect in [true, false] {
        let mut fixture = Fixture::new().await;
        let mut reply = Reply::body("data: waiting\n\n");
        reply
            .headers
            .push(("content-type".into(), "text/event-stream".into()));
        reply.disconnect = disconnect;
        if !disconnect {
            reply.delay = Duration::from_secs(5);
        }
        fixture.origin = Origin::spawn(reply).await;
        let broker = Broker::new(fixture.configuration()).unwrap();
        let session = broker.create_session(options()).unwrap();
        let request = fixture.request();
        let result = session.execute(request.clone()).await;
        if disconnect {
            assert!(matches!(result, Err(error) if error.code == ErrorCode::OutcomeUnknown));
        } else {
            drop(result.unwrap());
        }
        assert_eq!(
            session
                .request_status(request.request_id.clone())
                .await
                .unwrap()
                .state,
            OperationState::OutcomeUnknown
        );
        session.execute(request).await.unwrap();
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn anthropic_profile_uses_a_private_key_and_fixed_version() {
    let fixture = Fixture::new().await;
    let mut configuration = fixture.configuration();
    configuration.profiles[0].routes[0].path = "/v1/messages".into();
    configuration.profiles[0].routes[0]
        .allowed_headers
        .push("anthropic-version".into());
    configuration.profiles[0].auth = Authentication::ApiKey {
        item_id: "provider-key".into(),
        header: "x-api-key".into(),
        prefix: "".into(),
        provider: ProviderKind::AnthropicMessages,
    };
    let broker = Broker::new(configuration).unwrap();
    let session = broker.create_session(options()).unwrap();
    let mut request = fixture.request();
    request.target = format!("{}/v1/messages", fixture.origin.origin());
    request.body_base64 = STANDARD_FOR_TEST.encode(
        br#"{"model":"fixture","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}"#,
    );
    let mut invalid = request.clone();
    invalid.request_id = aap_types::ids::random_id(16).unwrap();
    invalid
        .headers
        .push(("anthropic-version".into(), "injected-version".into()));
    assert!(
        matches!(session.execute(invalid).await, Err(error) if error.code == ErrorCode::PolicyDenied),
        "agent overrode fixed provider version"
    );
    session
        .execute(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let requests = fixture.origin.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers["x-api-key"], "synthetic-api-key");
    assert_eq!(requests[0].headers["anthropic-version"], "2023-06-01");
}

#[tokio::test]
async fn matching_approval_dispatches_once_but_rotation_invalidates_it() {
    for rotate in [false, true] {
        let fixture = Fixture::new().await;
        let (received_tx, mut received) = tokio::sync::mpsc::unbounded_channel();
        let (decision, decision_rx) = tokio::sync::oneshot::channel();
        let mut configuration = fixture.configuration();
        configuration.require_approval = true;
        configuration.approval = Some(Arc::new(Gate {
            received: received_tx,
            decision: Mutex::new(Some(decision_rx)),
        }));
        let broker = Broker::new(configuration).unwrap();
        let session = broker.create_session(options()).unwrap();
        let request = fixture.request();
        let running = session.clone();
        let execution = tokio::spawn(async move { running.execute(request).await });
        let approval = tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        if rotate {
            fixture
                .store
                .put(
                    &ItemRef::new("private-reference".into()).unwrap(),
                    [(
                        Field::ApiKey,
                        SecretBytes::new(b"rotated-synthetic-key".to_vec()).unwrap(),
                    )]
                    .into(),
                    Some(&approval.credential_lease),
                )
                .await
                .unwrap();
        }
        decision.send(true).unwrap();
        let result = execution.await.unwrap();
        if rotate {
            assert!(result.is_err());
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
            assert!(fixture.origin.requests.lock().unwrap().is_empty());
        } else {
            result.unwrap().into_body().collect().await.unwrap();
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
        }
    }
}
