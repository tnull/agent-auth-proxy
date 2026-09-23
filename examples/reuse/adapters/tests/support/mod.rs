//! Test-only secret custody. No operational store is exported by this package.
use aap_engine::{Broker, Session, SessionOptions};
use aap_observe::Recorder;
use aap_policy::{
    AddressPolicy, Authentication, Catalog, CredentialRef, Item, ItemApproval, ResourceProfile,
    Route,
};
use aap_secrets::{
    Availability, Field, ItemMetadata, ItemRef, Lease, SecretBytes, SecretStore, Snapshot,
    StoreError, StoreStatus, Version,
};
use aap_test_support::{Origin, Reply};
use aap_types::{BoxFuture, ExecuteRequest, Result, profile::ProviderKind};
use base64::{Engine, engine::general_purpose::STANDARD};
use reuse_adapters::{ApprovalInbox, PendingApproval};
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;

pub const KEY: &str = "synthetic-adapter-first-key";
pub const NEXT: &str = "synthetic-adapter-next-key";
const PRIVATE: &str = "private-adapter-item";
struct State {
    metadata: ItemMetadata,
    availability: Availability,
    exists: bool,
    key: &'static str,
}
pub struct Store {
    state: Mutex<State>,
    pub resolutions: AtomicUsize,
    pub reads: AtomicUsize,
}
impl Store {
    fn new() -> Self {
        Self {
            state: Mutex::new(State {
                metadata: ItemMetadata {
                    lease: Lease {
                        version: Version::fresh().unwrap(),
                        generation: Version::fresh().unwrap(),
                    },
                    fields: vec![Field::ApiKey],
                    valid_until: None,
                },
                availability: Availability::Ready,
                exists: true,
                key: KEY,
            }),
            resolutions: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
        }
    }
    fn check(state: &State, item: &ItemRef, expected: Option<&Lease>) -> aap_secrets::Result<()> {
        match state.availability {
            Availability::Ready => {}
            Availability::Locked => return Err(StoreError::Locked),
            Availability::Unavailable => return Err(StoreError::Unavailable),
            Availability::InteractionRequired => return Err(StoreError::InteractionRequired),
        }
        if item.expose() != PRIVATE || !state.exists {
            return Err(StoreError::NotFound);
        }
        if expected.is_some_and(|lease| lease != &state.metadata.lease) {
            return Err(StoreError::Changed);
        }
        Ok(())
    }
    pub fn rotate(&self) {
        let mut state = self.state.lock().unwrap();
        state.metadata.lease.version = Version::fresh().unwrap();
        state.key = NEXT;
    }
    pub fn availability(&self, availability: Availability) {
        let mut state = self.state.lock().unwrap();
        state.availability = availability;
        state.metadata.lease.generation = Version::fresh().unwrap();
    }
    pub fn delete(&self) {
        self.state.lock().unwrap().exists = false;
    }
    pub fn resolved(&self) -> usize {
        self.resolutions.load(Ordering::SeqCst)
    }
}
impl SecretStore for Store {
    fn status(&self) -> BoxFuture<'_, aap_secrets::Result<StoreStatus>> {
        Box::pin(async {
            let state = self.state.lock().unwrap();
            Ok(StoreStatus {
                availability: state.availability,
                generation: state.metadata.lease.generation.clone(),
            })
        })
    }
    fn metadata<'a>(
        &'a self,
        item: &'a ItemRef,
    ) -> BoxFuture<'a, aap_secrets::Result<ItemMetadata>> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let state = self.state.lock().unwrap();
            Self::check(&state, item, None)?;
            Ok(state.metadata.clone())
        })
    }
    fn resolve<'a>(
        &'a self,
        item: &'a ItemRef,
        expected: &'a Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<Snapshot>> {
        Box::pin(async move {
            self.resolutions.fetch_add(1, Ordering::SeqCst);
            let state = self.state.lock().unwrap();
            Self::check(&state, item, Some(expected))?;
            Snapshot::new(
                state.metadata.clone(),
                [(
                    Field::ApiKey,
                    SecretBytes::new(state.key.as_bytes().to_vec())?,
                )]
                .into(),
            )
        })
    }
    fn revalidate<'a>(
        &'a self,
        item: &'a ItemRef,
        expected: &'a Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<()>> {
        Box::pin(async move { Self::check(&self.state.lock().unwrap(), item, Some(expected)) })
    }
}
struct Fixed(SocketAddr);
impl aap_transport::Resolver for Fixed {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            assert_eq!(host, "fixture.test");
            assert_eq!(port, self.0.port());
            Ok(vec![self.0])
        })
    }
}
pub struct Fixture {
    pub broker: Broker,
    pub session: Session,
    pub store: Arc<Store>,
    pub recorder: Recorder,
    pub pending: mpsc::Receiver<PendingApproval>,
    pub origin: Origin,
}
impl Fixture {
    pub async fn new(approval: bool) -> Self {
        let store = Arc::new(Store::new());
        let expected = store.clone();
        let origin = Origin::with_handler(move |request| {
            assert_eq!(request.target.path(), "/v1/chat/completions");
            let key = expected.state.lock().unwrap().key;
            assert_eq!(request.headers["authorization"], format!("Bearer {key}"));
            let mut reply = Reply::body(format!("data: {key}\n\n"));
            reply
                .headers
                .push(("content-type".into(), "text/event-stream".into()));
            reply
        })
        .await;
        let (inbox, pending) = ApprovalInbox::new(1).unwrap();
        let recorder = Recorder::new(id(), 1024, 1024 * 1024).unwrap();
        let broker = Broker::new(aap_engine::Configuration {
            catalog: Catalog {
                schema_version: 1,
                configuration_revision: 1,
                items: vec![Item {
                    item_id: "account".into(),
                    label: "Synthetic".into(),
                    account_alias: "test".into(),
                    profile: "provider".into(),
                    credential: CredentialRef {
                        store: "custom".into(),
                        key: PRIVATE.into(),
                    },
                    approval: ItemApproval::Inherit,
                }],
            },
            profiles: vec![ResourceProfile {
                id: "provider".into(),
                origin: origin.origin(),
                addresses: AddressPolicy::Pinned(vec![origin.address.ip()]),
                routes: vec![Route {
                    method: "POST".into(),
                    path: "/v1/chat/completions".into(),
                    query: None,
                    max_request_bytes: 16 * 1024,
                    max_response_bytes: 16 * 1024,
                    allowed_headers: vec!["content-type".into()],
                    streaming: true,
                    require_approval: false,
                }],
                auth: Authentication::ApiKey {
                    item_id: "account".into(),
                    header: "authorization".into(),
                    prefix: "Bearer ".into(),
                    provider: ProviderKind::OpenAiChat,
                },
            }],
            tcp_profiles: vec![],
            stores: HashMap::from([("custom".into(), store.clone() as Arc<dyn SecretStore>)]),
            resolver: Arc::new(Fixed(origin.address)),
            transport: Arc::new(
                aap_transport::HttpsTransport::new([origin.certificate.clone()]).unwrap(),
            ),
            tcp_connector: Arc::new(aap_transport::tcp::SystemTcpConnector),
            inspector: Arc::new(aap_providers::TextOnly),
            approval: Some(Arc::new(inbox)),
            require_approval: approval,
            recorder: recorder.clone(),
        })
        .unwrap();
        let session = broker
            .create_session(SessionOptions {
                resources: vec!["provider".into()],
                items: None,
                lifetime: Duration::from_secs(60),
                require_approval: false,
                require_observation: true,
            })
            .unwrap();
        Self {
            broker,
            session,
            store,
            recorder,
            pending,
            origin,
        }
    }
    pub fn request(&self) -> ExecuteRequest {
        ExecuteRequest { request_id: id(), resource: "provider".into(), auth_context: None, method: "POST".into(), target: format!("{}/v1/chat/completions", self.origin.origin()), headers: vec![("content-type".into(),"application/json".into())], body_base64: STANDARD.encode(br#"{"model":"fixture","messages":[{"role":"user","content":"hello"}],"stream":true}"#) }
    }
    pub fn receipts(&self) -> usize {
        self.origin.requests.lock().unwrap().len()
    }
}
pub fn id() -> String {
    aap_types::ids::random_id(16).unwrap()
}
pub async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("fixture deadline exceeded")
}
pub fn safe(bytes: &[u8]) {
    for private in [KEY, NEXT, PRIVATE] {
        assert!(
            !String::from_utf8_lossy(bytes).contains(private),
            "private value leaked"
        );
    }
}
