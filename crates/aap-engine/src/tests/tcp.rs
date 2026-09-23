use super::*;
use crate::tcp::{ConnectionApproval, PendingTcp, TcpAdmission};
use aap_policy::{TcpLimits, TcpProfile};
use aap_types::stream::{self, Cause};

struct NoStoreCalls(Arc<AtomicUsize>);
impl NoStoreCalls {
    fn unavailable<T: Send>(&self) -> BoxFuture<'_, aap_secrets::Result<T>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(aap_secrets::StoreError::Unavailable) })
    }
}
impl SecretStore for NoStoreCalls {
    fn status(&self) -> BoxFuture<'_, aap_secrets::Result<aap_secrets::StoreStatus>> {
        self.unavailable()
    }
    fn metadata<'a>(
        &'a self,
        _item: &'a ItemRef,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::ItemMetadata>> {
        self.unavailable()
    }
    fn resolve<'a>(
        &'a self,
        _item: &'a ItemRef,
        _lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::Snapshot>> {
        self.unavailable()
    }
    fn revalidate<'a>(
        &'a self,
        _item: &'a ItemRef,
        _lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<()>> {
        self.unavailable()
    }
}

fn open() -> stream::Open {
    stream::Open {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "raw-fixture".into(),
    }
}

fn admitted(session: &Session, request: stream::Open) -> PendingTcp {
    match session.admit_tcp(request).expect("TCP admission failed") {
        TcpAdmission::New(pending) => pending,
        TcpAdmission::Existing(_) => panic!("new request unexpectedly existed"),
    }
}

struct TcpFixture {
    listener: tokio::net::TcpListener,
    address: SocketAddr,
}
impl TcpFixture {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        Self { listener, address }
    }
    fn configuration(&self, fixture: &Fixture) -> Configuration {
        let mut configuration = fixture.configuration();
        configuration.tcp_profiles.push(TcpProfile {
            id: "raw-fixture".into(),
            endpoint: format!("raw.test:{}", self.address.port()),
            addresses: AddressPolicy::Pinned(vec![self.address.ip()]),
            limits: TcpLimits::default(),
            inspection: stream::Inspection::PlaintextBytes,
            require_approval: false,
            require_observation: true,
        });
        configuration.resolver = Arc::new(FixedResolver(self.address));
        configuration.stores.insert(
            "default".into(),
            Arc::new(NoStoreCalls(fixture.resolutions.clone())),
        );
        configuration
    }
}

fn tcp_options() -> SessionOptions {
    let mut options = options();
    options.resources.push("raw-fixture".into());
    options
}

#[tokio::test]
async fn tcp_opening_reports_remaining_authority_and_unpolled_connections_expire() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let mut config = tcp.configuration(&fixture);
    config.tcp_profiles[0].limits.lifetime_ms = 5000;
    config.tcp_profiles[0].limits.idle_timeout_ms = 1000;
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    let connected = admitted(&session, request.clone()).connect().await.unwrap();
    let (_peer, _) = tcp.listener.accept().await.unwrap();
    tokio::time::pause();
    let first = connected.opened().unwrap().remaining_lifetime_ms;
    tokio::time::advance(Duration::from_millis(200)).await;
    let later = connected.opened().unwrap().remaining_lifetime_ms;
    assert!(
        later <= first.saturating_sub(200),
        "OPENED extended the original connection lifetime"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(connected.opened().is_err());
    assert_eq!(
        session
            .request_status(request.request_id)
            .await
            .unwrap()
            .state,
        OperationState::OutcomeUnknown
    );
    assert_eq!(session.core.active.available_permits(), 8);
    assert_eq!(broker.host.tcp_payload.available_permits(), 8 * 1024 * 1024);
}

#[tokio::test]
async fn tcp_identity_status_and_attachment_ownership_share_the_common_namespace() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    let pending = admitted(&session, request.clone());
    assert_eq!(
        session
            .request_status(request.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::Validated
    );
    assert!(
        matches!(session.admit_tcp(request.clone()).unwrap(), TcpAdmission::Existing(status) if status.request_id == request.request_id)
    );
    let mut changed = request.clone();
    changed.resource = "provider".into();
    assert!(
        matches!(session.admit_tcp(changed), Err(error) if error.code == ErrorCode::RequestConflict)
    );
    let mut http = fixture.request();
    http.request_id = request.request_id.clone();
    assert!(
        matches!(session.execute(http).await, Err(error) if error.code == ErrorCode::RequestConflict)
    );
    assert!(
        matches!(session.get_login(GetLogin { request_id: request.request_id.clone(), item_id: "provider-key".into(), uri: fixture.origin.origin() }).await, Err(error) if error.code == ErrorCode::RequestConflict)
    );
    drop(pending);
    assert_eq!(
        session
            .request_status(request.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::Cancelled
    );
    assert!(
        matches!(session.admit_tcp(request.clone()).unwrap(), TcpAdmission::Existing(status) if status.state == OperationState::Cancelled)
    );
    let other = broker.create_session(tcp_options()).unwrap();
    drop(admitted(&other, request));
    let ungranted = broker.create_session(options()).unwrap();
    assert!(
        matches!(ungranted.admit_tcp(open()), Err(error) if error.code == ErrorCode::PolicyDenied)
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

type ApprovalNotice = (Arc<ConnectionApproval>, tokio::sync::oneshot::Sender<bool>);
struct ConnectionGate(tokio::sync::mpsc::UnboundedSender<ApprovalNotice>);
impl ApprovalProvider for ConnectionGate {
    fn approve(
        &self,
        _request: Arc<ApprovalRequest>,
        _cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<bool>> {
        Box::pin(async { Err(ErrorCode::InteractionUnavailable.into()) })
    }
    fn approve_connection(
        &self,
        request: Arc<ConnectionApproval>,
        _cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<bool>> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.0.send((request, sender)).unwrap();
        Box::pin(async {
            receiver
                .await
                .map_err(|_| ErrorCode::InteractionUnavailable.into())
        })
    }
}

#[tokio::test]
async fn tcp_approval_binds_connection_facts_without_a_credential_lease() {
    use tokio::io::AsyncReadExt;
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let (events, mut notices) = tokio::sync::mpsc::unbounded_channel();
    let mut config = tcp.configuration(&fixture);
    config.require_approval = true;
    config.approval = Some(Arc::new(ConnectionGate(events)));
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    let pending = admitted(&session, request.clone());
    let connect = tokio::spawn(pending.connect());
    let (approval, decide) = tokio::time::timeout(Duration::from_secs(2), notices.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(approval.operation.request_id, request.request_id);
    assert_eq!(
        approval.endpoint,
        format!("raw.test:{}", tcp.address.port())
    );
    assert_eq!(
        approval.limits.max_data_bytes,
        stream::MAX_DATA_BYTES as u32
    );
    assert!(approval.require_observation);
    assert_eq!(
        session
            .request_status(request.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::PendingApproval
    );
    assert_eq!(
        session.core.active.available_permits(),
        8,
        "approval held an active socket slot"
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    decide.send(true).unwrap();
    let connected = connect.await.unwrap().unwrap();
    let opened = connected.opened().unwrap();
    assert_eq!(opened.request_id, request.request_id);
    assert_eq!(opened.observation, stream::Observation::Required);
    assert_eq!(session.core.active.available_permits(), 7);
    let (mut peer, _) = tcp.listener.accept().await.unwrap();
    assert_eq!(
        session
            .cancel(request.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::OutcomeUnknown
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(connected.opened().is_err());
    assert_eq!(session.core.active.available_permits(), 8);
    drop(connected);
    assert_eq!(
        session
            .request_status(request.request_id)
            .await
            .unwrap()
            .state,
        OperationState::OutcomeUnknown
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_pending_drop_denial_and_unavailable_approval_never_dial() {
    for mode in ["unavailable", "deny", "drop", "cancel", "revoke"] {
        let fixture = Fixture::new().await;
        let tcp = TcpFixture::new().await;
        let (events, mut notices) = tokio::sync::mpsc::unbounded_channel();
        let mut config = tcp.configuration(&fixture);
        config.tcp_profiles[0].require_approval = true;
        if mode != "unavailable" {
            config.approval = Some(Arc::new(ConnectionGate(events)));
        }
        let broker = Broker::new(config).unwrap();
        let session = broker.create_session(tcp_options()).unwrap();
        let request = open();
        let task = tokio::spawn(admitted(&session, request.clone()).connect());
        if mode == "unavailable" {
            assert!(
                matches!(task.await.unwrap(), Err(outcome) if outcome.cause == Cause::InteractionUnavailable && outcome.operation.state == OperationState::Failed)
            );
        } else {
            let (_, decide) = tokio::time::timeout(Duration::from_secs(2), notices.recv())
                .await
                .unwrap()
                .unwrap();
            match mode {
                "deny" => {
                    decide.send(false).unwrap();
                }
                "drop" => {
                    task.abort();
                    drop(decide);
                }
                "cancel" => {
                    session.cancel(request.request_id.clone()).await.unwrap();
                    let _ = decide.send(true);
                }
                _ => {
                    broker.revoke(&session).unwrap();
                    let _ = decide.send(true);
                }
            }
            match task.await {
                Ok(result) => assert!(result.is_err(), "late/denied approval connected"),
                Err(error) => assert!(mode == "drop" && error.is_cancelled()),
            }
        }
        assert_eq!(session.core.active.available_permits(), 8);
        assert_eq!(session.core.pending.available_permits(), 16);
        assert_eq!(session.core.pending_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), tcp.listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn tcp_pending_capacity_is_shared_by_clones_and_duplicates_need_no_slot() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let mut attachments = Vec::new();
    let first = open();
    attachments.push(admitted(&session, first.clone()));
    for _ in 1..16 {
        attachments.push(admitted(&session.clone(), open()));
    }
    assert!(
        matches!(session.admit_tcp(open()), Err(error) if error.code == ErrorCode::LimitExceeded)
    );
    assert!(matches!(
        session.admit_tcp(first.clone()).unwrap(),
        TcpAdmission::Existing(_)
    ));
    // Cancellation must free an unstarted attachment even if its owner retains
    // the handle. Its old request ID still cannot acquire another attachment.
    session.cancel(first.request_id.clone()).await.unwrap();
    let replacement = admitted(&session, open());
    drop(replacement);
    drop(attachments.pop());
    attachments.push(admitted(&session, open()));
    let mut changed = first;
    changed.resource = "different".into();
    assert!(
        matches!(session.admit_tcp(changed), Err(error) if error.code == ErrorCode::RequestConflict)
    );
    drop(attachments);
    assert_eq!(session.core.active.available_permits(), 8);
}

#[tokio::test]
async fn tcp_grants_are_credential_free_and_cannot_bypass_inspected_profiles() {
    let fixture = Fixture::new().await;
    let profile = TcpProfile {
        id: "raw-fixture".into(),
        endpoint: "raw.test:9000".into(),
        addresses: AddressPolicy::Pinned(vec!["127.0.0.1".parse().unwrap()]),
        limits: TcpLimits::default(),
        inspection: aap_types::stream::Inspection::PlaintextBytes,
        require_approval: false,
        require_observation: true,
    };
    let mut configuration = fixture.configuration();
    configuration.tcp_profiles.push(profile.clone());
    let broker = Broker::new(configuration).unwrap();
    let mut options = options();
    options.resources = vec![profile.id.clone()];
    let session = broker
        .create_session(options)
        .expect("enrolled TCP resource cannot be granted");
    let mut request = fixture.request();
    request.resource = profile.id.clone();
    assert!(session.execute(request).await.is_err());
    assert!(
        session
            .search_items(SearchItems {
                uri: fixture.origin.origin(),
                query: None,
                cursor: None
            })
            .await
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());

    let mut configuration = fixture.configuration();
    let mut collision = profile.clone();
    collision.endpoint = format!("fixture.test:{}", fixture.origin.address.port());
    configuration.tcp_profiles.push(collision);
    assert!(
        Broker::new(configuration).is_err(),
        "raw endpoint bypasses inspected provider"
    );
    let mut configuration = fixture.configuration();
    configuration.catalog.items[0].profile = profile.id.clone();
    configuration.tcp_profiles.push(profile);
    assert!(
        Broker::new(configuration).is_err(),
        "credential item attached to raw TCP"
    );
}

struct BothResolvers {
    http: SocketAddr,
    tcp: SocketAddr,
}
impl Resolver for BothResolvers {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            let address = if host == "raw.test" {
                self.tcp
            } else {
                self.http
            };
            assert_eq!(port, address.port());
            Ok(vec![address])
        })
    }
}

#[tokio::test]
async fn tcp_and_http_approvals_share_count_and_retained_byte_limits() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let mut config = tcp.configuration(&fixture);
    config.stores = fixture.configuration().stores;
    config.resolver = Arc::new(BothResolvers {
        http: fixture.origin.address,
        tcp: tcp.address,
    });
    let (sender, mut received) = tokio::sync::mpsc::unbounded_channel();
    config.approval = Some(Arc::new(PendingProvider(sender)));
    config.require_approval = true;
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let request = fixture.request();
        let id = request.request_id.clone();
        let service = session.clone();
        tasks.push((
            id,
            tokio::spawn(async move { service.execute(request).await }),
        ));
        tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let blocked = admitted(&session, open()).connect().await;
    assert!(
        matches!(blocked, Err(outcome) if outcome.cause == Cause::CapacityExhausted && outcome.operation.state == OperationState::Failed)
    );
    assert_eq!(session.core.active.available_permits(), 8);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    for (id, task) in tasks {
        session.cancel(id).await.unwrap();
        assert!(task.await.unwrap().is_err());
    }
    assert_eq!(session.core.pending_bytes.load(Ordering::SeqCst), 0);
    let _large = session.reserve_approval(4 * 1024 * 1024 - 1).unwrap();
    assert!(
        matches!(admitted(&session, open()).connect().await, Err(outcome) if outcome.cause == Cause::CapacityExhausted)
    );
    assert_eq!(session.core.pending.available_permits(), 15);
}

#[tokio::test]
async fn tcp_global_pending_capacity_and_cross_kind_conflicts_are_retained() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
    let mut sessions = Vec::new();
    let mut pending = Vec::new();
    for _ in 0..8 {
        let session = broker.create_session(tcp_options()).unwrap();
        for _ in 0..16 {
            pending.push(admitted(&session, open()));
        }
        sessions.push(session);
    }
    let extra = broker.create_session(tcp_options()).unwrap();
    assert!(
        matches!(extra.admit_tcp(open()), Err(error) if error.code == ErrorCode::LimitExceeded)
    );
    drop(pending.pop());
    drop(admitted(&extra, open()));
    drop(pending);
    assert_eq!(broker.host.tcp_pending.available_permits(), 128);

    let request = open();
    let _ = extra
        .get_login(GetLogin {
            request_id: request.request_id.clone(),
            item_id: "missing".into(),
            uri: "https://fixture.test/".into(),
        })
        .await;
    assert!(
        matches!(extra.admit_tcp(request), Err(error) if error.code == ErrorCode::RequestConflict)
    );
    let request = open();
    let mut http = fixture.request();
    http.request_id = request.request_id.clone();
    http.resource = "missing".into();
    assert!(extra.execute(http).await.is_err());
    assert!(
        matches!(extra.admit_tcp(request), Err(error) if error.code == ErrorCode::RequestConflict)
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

struct MemoryConnector {
    peers: Mutex<Vec<tokio::io::DuplexStream>>,
    calls: AtomicUsize,
}
impl aap_transport::tcp::TcpConnector for MemoryConnector {
    fn connect(
        &self,
        _endpoint: aap_transport::tcp::TcpEndpoint,
        _deadline: Instant,
        _cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<aap_transport::tcp::TcpSocket>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (stream, peer) = tokio::io::duplex(1);
            self.peers.lock().unwrap().push(peer);
            Ok(Box::new(stream) as aap_transport::tcp::TcpSocket)
        })
    }
}

#[tokio::test]
async fn tcp_active_and_payload_limits_release_without_waiting_or_resetting_by_session() {
    let mut fixture = Fixture::new().await;
    // Required records cannot be evicted. Give the capacity fixture enough
    // bounded recording headroom to reach all 64 connections without an ACK.
    fixture.recorder = Recorder::new(
        aap_types::ids::random_id(16).unwrap(),
        2048,
        4 * 1024 * 1024,
    )
    .unwrap();
    let tcp = TcpFixture::new().await;
    let connector = Arc::new(MemoryConnector {
        peers: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
    });
    let mut config = tcp.configuration(&fixture);
    config.tcp_connector = connector.clone();
    let broker = Broker::new(config).unwrap();
    let mut connected = Vec::new();
    for _ in 0..8 {
        let session = broker.create_session(tcp_options()).unwrap();
        for _ in 0..8 {
            connected.push(admitted(&session, open()).connect().await.unwrap());
        }
        match admitted(&session, open()).connect().await {
            Err(outcome) => assert_eq!(outcome.cause, Cause::CapacityExhausted),
            Ok(_) => panic!("shared active capacity was exceeded"),
        }
    }
    let extra = broker.create_session(tcp_options()).unwrap();
    assert!(
        matches!(admitted(&extra, open()).connect().await, Err(outcome) if outcome.cause == Cause::CapacityExhausted)
    );
    assert_eq!(connector.calls.load(Ordering::SeqCst), 64);
    assert_eq!(broker.host.tcp_payload.available_permits(), 0);
    drop(connected.pop());
    assert_eq!(broker.host.tcp_payload.available_permits(), 128 * 1024);
    drop(admitted(&extra, open()).connect().await.unwrap());
    drop(connected);
    assert_eq!(broker.host.tcp_active.available_permits(), 64);
    assert_eq!(broker.host.tcp_payload.available_permits(), 8 * 1024 * 1024);
    let _payload = broker
        .host
        .tcp_payload
        .clone()
        .acquire_many_owned(8 * 1024 * 1024)
        .await
        .unwrap();
    let before = connector.calls.load(Ordering::SeqCst);
    assert!(
        matches!(admitted(&extra, open()).connect().await, Err(outcome) if outcome.cause == Cause::CapacityExhausted)
    );
    assert_eq!(connector.calls.load(Ordering::SeqCst), before);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_approval_timeout_releases_its_reservations() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let (events, mut notices) = tokio::sync::mpsc::unbounded_channel();
    let mut config = tcp.configuration(&fixture);
    config.require_approval = true;
    config.approval = Some(Arc::new(ConnectionGate(events)));
    let broker = Broker::new(config).unwrap();
    let mut options = tcp_options();
    options.lifetime = Duration::from_secs(3600);
    let session = broker.create_session(options).unwrap();
    tokio::time::pause();
    let request = open();
    let pending = tokio::spawn(admitted(&session, request.clone()).connect());
    let (_, decide) = notices.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(300)).await;
    assert!(
        matches!(pending.await.unwrap(), Err(outcome) if outcome.cause == Cause::ApprovalTimeout && outcome.operation.state == OperationState::Expired)
    );
    assert!(decide.send(true).is_err());
    assert_eq!(session.core.pending.available_permits(), 16);
    assert_eq!(session.core.pending_bytes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

struct ResolverGate {
    started: tokio::sync::Notify,
    result: Mutex<Option<tokio::sync::oneshot::Receiver<Vec<SocketAddr>>>>,
}
impl Resolver for ResolverGate {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        let result = self.result.lock().unwrap().take().unwrap();
        self.started.notify_one();
        Box::pin(async {
            result
                .await
                .map_err(|_| ErrorCode::UpstreamUnavailable.into())
        })
    }
}

async fn expired_preparation(approval: bool) {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let mut config = tcp.configuration(&fixture);
    let connector = Arc::new(MemoryConnector {
        peers: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
    });
    config.tcp_connector = connector.clone();
    let (events, mut notices) = tokio::sync::mpsc::unbounded_channel();
    let (resolve, resolution) = tokio::sync::oneshot::channel();
    let resolver = Arc::new(ResolverGate {
        started: tokio::sync::Notify::new(),
        result: Mutex::new(Some(resolution)),
    });
    if approval {
        config.require_approval = true;
        config.approval = Some(Arc::new(ConnectionGate(events)));
    } else {
        config.resolver = resolver.clone();
    }
    let broker = Broker::new(config).unwrap();
    let mut options = tcp_options();
    options.lifetime = Duration::from_secs(3600);
    let session = broker.create_session(options).unwrap();
    tokio::time::pause();
    let pending = tokio::spawn(admitted(&session, open()).connect());
    if approval {
        let (_, decision) = notices.recv().await.unwrap();
        decision.send(true).unwrap();
        tokio::time::advance(Duration::from_secs(300)).await;
    } else {
        resolver.started.notified().await;
        resolve.send(vec![tcp.address]).unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
    }
    match pending.await.unwrap() {
        Err(outcome) => {
            assert_eq!(outcome.operation.state, OperationState::Expired);
            assert_eq!(
                outcome.cause,
                if approval {
                    Cause::ApprovalTimeout
                } else {
                    Cause::Timeout
                }
            );
        }
        Ok(_) => panic!("an expired preparation result opened a connection"),
    }
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    assert_eq!(session.core.pending.available_permits(), 16);
    assert_eq!(session.core.active.available_permits(), 8);
    tokio::time::resume();
}

#[tokio::test]
async fn tcp_ready_approval_cannot_win_at_an_expired_deadline() {
    expired_preparation(true).await;
}

#[tokio::test]
async fn tcp_ready_dns_cannot_win_at_an_expired_deadline() {
    expired_preparation(false).await;
}

struct ConnectorGate {
    started: tokio::sync::Notify,
    result: Mutex<Option<tokio::sync::oneshot::Receiver<aap_transport::tcp::TcpSocket>>>,
}
impl aap_transport::tcp::TcpConnector for ConnectorGate {
    fn connect(
        &self,
        _endpoint: aap_transport::tcp::TcpEndpoint,
        _deadline: Instant,
        _cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<aap_transport::tcp::TcpSocket>> {
        let result = self.result.lock().unwrap().take().unwrap();
        self.started.notify_one();
        Box::pin(async {
            result
                .await
                .map_err(|_| ErrorCode::UpstreamUnavailable.into())
        })
    }
}

#[tokio::test]
async fn tcp_ready_connector_cannot_win_at_an_expired_deadline() {
    use tokio::io::AsyncReadExt;

    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let mut config = tcp.configuration(&fixture);
    let (deliver, result) = tokio::sync::oneshot::channel();
    let connector = Arc::new(ConnectorGate {
        started: tokio::sync::Notify::new(),
        result: Mutex::new(Some(result)),
    });
    config.tcp_connector = connector.clone();
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    tokio::time::pause();
    let pending = tokio::spawn(admitted(&session, request.clone()).connect());
    connector.started.notified().await;
    assert_eq!(
        session
            .request_status(request.request_id)
            .await
            .unwrap()
            .state,
        OperationState::Dispatching
    );
    let (socket, mut peer) = tokio::io::duplex(1);
    assert!(
        deliver
            .send(Box::new(socket) as aap_transport::tcp::TcpSocket)
            .is_ok()
    );
    tokio::time::advance(Duration::from_secs(10)).await;
    match pending.await.unwrap() {
        Err(outcome) => {
            assert_eq!(outcome.operation.state, OperationState::OutcomeUnknown);
            assert_eq!(outcome.cause, Cause::Timeout);
        }
        Ok(_) => panic!("a late connector result opened an expired connection"),
    }
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    assert_eq!(session.core.active.available_permits(), 8);
    assert_eq!(broker.host.tcp_active.available_permits(), 64);
    assert_eq!(broker.host.tcp_payload.available_permits(), 8 * 1024 * 1024);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}
