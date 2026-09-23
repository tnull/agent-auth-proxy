use super::*;
use aap_types::{AgentService, SearchItems};
use std::os::unix::fs::DirBuilderExt;

mod observation;
mod retirement;

struct Fixture {
    root: PathBuf,
    control: Arc<Control>,
}
impl Fixture {
    async fn new() -> Self {
        let parent = std::env::var_os("AAP_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = parent.join(format!(
            "aap-reload-{}",
            aap_types::ids::random_id(16).unwrap()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let directory = Arc::new(PrivateDir::open(&root.join("c"), true).unwrap());
        let runtime = Arc::new(PrivateDir::open(&root.join("r"), true).unwrap());
        let store = Arc::new(
            SqliteStore::open(
                Arc::new(PrivateDir::open(&root.join("s"), true).unwrap()),
                SecretBytes::new(vec![37; 32]).unwrap(),
                OpenMode::Create,
                tokio::runtime::Handle::current(),
            )
            .await
            .unwrap(),
        );
        let loaded = Loaded {
            configuration: DaemonConfig {
                schema_version: 1,
                configuration_revision: 1,
                store: SqliteConfiguration {
                    alias: "default".into(),
                    directory: root.join("s"),
                },
                runtime_directory: root.join("r"),
                upstream_roots_der_base64: vec![],
                interception: None,
                static_hosts: HashMap::new(),
                profiles: vec![],
                tcp_profiles: vec![],
                require_approval: false,
                observation: ObservationConfig {
                    acceptance: Acceptance::LocalMemory,
                    max_events: 64,
                    max_bytes: 65536,
                    required: false,
                },
            },
            catalog: Catalog {
                schema_version: 1,
                configuration_revision: 1,
                items: vec![],
            },
        };
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 64, 65536).unwrap();
        let broker = broker(&loaded, store.clone(), recorder.clone()).unwrap();
        let fixture = Self {
            root,
            control: Arc::new(Control {
                daemon_epoch: aap_types::ids::random_id(16).unwrap(),
                directory,
                runtime,
                store,
                recorder,
                state: Arc::new(Mutex::new(Generation {
                    loaded,
                    broker,
                    sessions: HashMap::new(),
                    observers: HashMap::new(),
                    interception: None,
                    last_reload: None,
                    retirement: None,
                })),
                reload_gate: tokio::sync::Mutex::new(()),
                prepared_hook: Mutex::new(None),
                cleanup_hook: Mutex::new(None),
            }),
        };
        fixture.write(1, 1);
        fixture
    }
    fn write(&self, configuration_revision: u64, catalog_revision: u64) {
        let state = self.control.state.lock().unwrap();
        let mut config = state.loaded.configuration.clone();
        let mut catalog = state.loaded.catalog.clone();
        config.configuration_revision = configuration_revision;
        catalog.configuration_revision = catalog_revision;
        for (name, bytes) in [
            ("daemon.json", serde_json::to_vec(&config).unwrap()),
            ("catalog.json", serde_json::to_vec(&catalog).unwrap()),
        ] {
            self.control
                .directory
                .write_atomic(name, &bytes, 1024 * 1024)
                .unwrap();
        }
    }
    fn broker(&self) -> Arc<Broker> {
        self.control.state.lock().unwrap().broker.clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.control.shutdown();
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
fn options() -> SessionOptions {
    SessionOptions {
        resources: vec![],
        items: None,
        lifetime: Duration::from_secs(60),
        require_approval: false,
        require_observation: false,
    }
}
async fn discover(session: &Session) -> Result<aap_types::SearchResult> {
    session
        .search_items(SearchItems {
            uri: "https://fixture.test".into(),
            query: None,
            cursor: None,
        })
        .await
}

#[tokio::test]
async fn reload_retires_broker_clones_outside_the_attachment_map() {
    let fixture = Fixture::new().await;
    let old = fixture.broker();
    let retained = old.create_session(options()).unwrap();
    discover(&retained).await.unwrap();
    fixture.write(2, 1);
    assert!(fixture.control.reload().await.is_err());
    assert!(!old.is_closed());
    discover(&retained).await.unwrap();
    fixture.write(2, 2);
    fixture.control.reload().await.unwrap();
    assert!(old.is_closed(), "reload left the retired broker open");
    assert!(
        matches!(old.create_session(options()), Err(error) if error.code == ErrorCode::SessionInvalid)
    );
    assert!(
        matches!(discover(&retained).await, Err(error) if error.code == ErrorCode::SessionInvalid)
    );
    let fresh = fixture.broker().create_session(options()).unwrap();
    discover(&fresh).await.unwrap();
    assert_eq!(
        fixture.control.store.status().await.unwrap().availability,
        aap_secrets::Availability::Ready
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_cannot_reopen_authority_after_shutdown_wins() {
    shutdown_wins(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_reload_cannot_reopen_authority_after_shutdown_wins() {
    shutdown_wins(true).await;
}

async fn shutdown_wins(prepared: bool) {
    let fixture = Fixture::new().await;
    let old = fixture.broker();
    fixture.write(2, 2);
    let result = if prepared {
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let release = Arc::new(std::sync::Barrier::new(2));
        let worker = release.clone();
        *fixture.control.prepared_hook.lock().unwrap() = Some(Box::new(move || {
            entered.send(()).unwrap();
            worker.wait();
            Ok(())
        }));
        let control = fixture.control.clone();
        let task = tokio::spawn(async move { control.reload().await });
        waiting.await.unwrap();
        fixture.control.shutdown().unwrap();
        release.wait();
        task.await.unwrap()
    } else {
        fixture.control.shutdown().unwrap();
        fixture.control.reload().await
    };
    assert!(
        matches!(result, Err(error) if error.code == ErrorCode::SessionInvalid),
        "reload reopened a host already shut down"
    );
    assert!(fixture.broker().is_closed());
    assert!(Arc::ptr_eq(&old, &fixture.broker()));
    assert_eq!(
        fixture
            .control
            .state
            .lock()
            .unwrap()
            .loaded
            .configuration
            .configuration_revision,
        1
    );
}

#[tokio::test]
async fn reload_cleanup_failure_preserves_commit_and_releases_host_lock() {
    let fixture = Fixture::new().await;
    let old = fixture.broker();
    let retained = old.create_session(options()).unwrap();
    discover(&retained).await.unwrap();
    fixture.write(2, 2);
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let recorded = observed.clone();
    let host = Arc::downgrade(&fixture.control);
    let retiring = old.clone();
    *fixture.control.cleanup_hook.lock().unwrap() = Some(Box::new(move || {
        let host = host.upgrade().unwrap();
        let published = host.state.try_lock().is_ok_and(|state| {
            state.loaded.configuration.configuration_revision == 2 && retiring.is_closed()
        });
        recorded.store(published, std::sync::atomic::Ordering::SeqCst);
        Err(ErrorCode::InternalError.into())
    }));
    let result = fixture.control.reload().await;
    assert!(
        result.is_ok(),
        "cleanup failure was reported as an unapplied reload"
    );
    let result = serde_json::to_value(result.unwrap()).unwrap();
    assert_eq!(result["configuration_revision"], 2);
    assert_eq!(result["retirement"]["configuration_revision"], 1);
    assert_eq!(result["retirement"]["authority_cleanup"], "failed");
    assert_eq!(result["retirement"]["authority_closed"], true);
    assert_eq!(result["retirement"]["drain_confirmed"], false);
    assert_eq!(
        fixture.control.state.lock().unwrap().last_reload.as_ref(),
        Some(&serde_json::from_value(result).unwrap())
    );
    assert!(
        observed.load(std::sync::atomic::Ordering::SeqCst),
        "cleanup ran before publication or under the host lock"
    );
    assert!(old.is_closed());
    assert!(
        matches!(discover(&retained).await, Err(error) if error.code == ErrorCode::SessionInvalid)
    );
    discover(&fixture.broker().create_session(options()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .control
            .state
            .lock()
            .unwrap()
            .loaded
            .configuration
            .configuration_revision,
        2
    );
}

#[tokio::test]
async fn reload_commit_then_shutdown_closes_both_generations() {
    let fixture = Fixture::new().await;
    let old = fixture.broker();
    let retained = old.create_session(options()).unwrap();
    discover(&retained).await.unwrap();
    fixture.write(2, 2);
    let host = Arc::downgrade(&fixture.control);
    *fixture.control.cleanup_hook.lock().unwrap() = Some(Box::new(move || {
        let host = host.upgrade().unwrap();
        // Assert without deadlocking if cleanup regresses under publication.
        assert!(host.state.try_lock().is_ok());
        host.shutdown()
    }));
    let result = serde_json::to_value(fixture.control.reload().await.unwrap()).unwrap();
    assert_eq!(result["configuration_revision"], 2);
    assert_eq!(result["retirement"]["authority_cleanup"], "complete");
    assert!(old.is_closed());
    assert!(fixture.broker().is_closed());
    assert!(
        matches!(discover(&retained).await, Err(error) if error.code == ErrorCode::SessionInvalid)
    );
    assert!(
        matches!(fixture.broker().create_session(options()), Err(error) if error.code == ErrorCode::SessionInvalid)
    );
    assert_eq!(
        fixture.control.state.lock().unwrap().last_reload.as_ref(),
        Some(&serde_json::from_value(result).unwrap())
    );
}
