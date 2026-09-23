//! Illustrative trusted composition using only public broker/store APIs.
//! This process belongs outside any untrusted agent sandbox.
use aap_engine::Broker;
use aap_observe::Recorder;
use aap_types::{ErrorCode, Result};
use std::sync::Arc;

#[path = "../../support/scenarios.rs"]
pub mod scenarios;

pub struct Settings {
    pub directory: Arc<aap_config::PrivateDir>,
    pub catalog: aap_policy::Catalog,
    pub profiles: Vec<aap_policy::ResourceProfile>,
    pub root_certificates: Vec<Vec<u8>>,
    pub resolver: Arc<dyn aap_transport::Resolver>,
}
pub struct Host {
    pub broker: Broker,
    pub http_drivers: aap_transport::http_drivers::HttpDrivers,
    pub recorder: Recorder,
    pub store: Arc<aap_store_sqlite::SqliteStore>,
}
impl Host {
    pub async fn open(
        settings: Settings,
        key: aap_secrets::SecretBytes,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self> {
        let store = Arc::new(
            aap_store_sqlite::SqliteStore::open(
                settings.directory,
                key,
                aap_store_sqlite::OpenMode::Existing,
                runtime,
            )
            .await
            .map_err(|_| ErrorCode::VaultUnavailable)?,
        );
        let recorder = Recorder::new(
            aap_types::ids::random_id(16).map_err(|_| ErrorCode::InternalError)?,
            4096,
            4 * 1024 * 1024,
        )?;
        let transport = aap_transport::HttpsTransport::new(
            settings.root_certificates.into_iter().map(Into::into),
        )?;
        let http_drivers = transport.http_drivers();
        let broker = Broker::new(aap_engine::Configuration {
            catalog: settings.catalog,
            profiles: settings.profiles,
            tcp_profiles: vec![],
            stores: std::collections::HashMap::from([(
                "default".into(),
                store.clone() as Arc<dyn aap_secrets::SecretStore>,
            )]),
            resolver: settings.resolver,
            transport: Arc::new(transport),
            tcp_connector: Arc::new(aap_transport::tcp::SystemTcpConnector),
            inspector: Arc::new(aap_providers::TextOnly),
            approval: None,
            require_approval: false,
            recorder: recorder.clone(),
        })?;
        Ok(Self {
            broker,
            http_drivers,
            recorder,
            store,
        })
    }
}
