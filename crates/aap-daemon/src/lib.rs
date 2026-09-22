//! Standalone host configuration, distinct from credential-free agent contracts.
use aap_policy::{Catalog, ResourceProfile};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, path::PathBuf};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub schema_version: u32,
    pub configuration_revision: u64,
    pub store: SqliteConfiguration,
    pub runtime_directory: PathBuf,
    pub upstream_roots_der_base64: Vec<String>,
    #[serde(default)]
    pub static_hosts: HashMap<String, Vec<IpAddr>>,
    pub profiles: Vec<ResourceProfile>,
    #[serde(default)]
    pub require_approval: bool,
    pub observation: ObservationConfig,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfiguration {
    pub alias: String,
    pub directory: PathBuf,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationConfig {
    pub acceptance: Acceptance,
    pub max_events: usize,
    pub max_bytes: usize,
    #[serde(default)]
    pub required: bool,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Acceptance {
    LocalMemory,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub schema_version: u32,
    pub daemon_epoch: String,
    pub control_socket: String,
    pub observation_socket: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSession {
    pub resources: Vec<String>,
    #[serde(default)]
    pub items: Option<Vec<String>>,
    pub lifetime_seconds: u64,
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub require_observation: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAttachment {
    pub session_id: String,
    pub ingress_socket: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionReference {
    pub session_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadEvents {
    pub cursor: Option<aap_observe::Cursor>,
    pub limit: usize,
}

pub struct Loaded {
    pub configuration: DaemonConfig,
    pub catalog: Catalog,
}
pub fn load(directory: &aap_config::PrivateDir) -> aap_types::Result<Loaded> {
    use aap_types::ErrorCode;
    let configuration: DaemonConfig = directory
        .read_json("daemon.json", 1024 * 1024)
        .map_err(|_| ErrorCode::RequestInvalid)?;
    let catalog: Catalog = directory
        .read_json("catalog.json", 1024 * 1024)
        .map_err(|_| ErrorCode::RequestInvalid)?;
    if configuration.schema_version != 1 || configuration.static_hosts.len() > 256 {
        return Err(ErrorCode::RequestInvalid.into());
    }
    catalog.validate(
        &configuration.profiles,
        &[configuration.store.alias.as_str()],
        configuration.configuration_revision,
    )?;
    aap_config::PrivateDir::open(&configuration.store.directory, false)
        .map_err(|_| ErrorCode::RequestInvalid)?;
    aap_config::PrivateDir::open(&configuration.runtime_directory, false)
        .map_err(|_| ErrorCode::RequestInvalid)?;
    for (host, addresses) in &configuration.static_hosts {
        let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let target = aap_policy::Target::parse(&format!("https://{authority}"))?;
        if target.host().trim_start_matches('[').trim_end_matches(']') != host
            || addresses.is_empty()
            || addresses.len() > 64
            || addresses
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
    }
    transport(&configuration)?;
    aap_observe::Recorder::new(
        aap_types::ids::random_id(16).map_err(|_| ErrorCode::InternalError)?,
        configuration.observation.max_events,
        configuration.observation.max_bytes,
    )?;
    Ok(Loaded {
        configuration,
        catalog,
    })
}

pub fn transport(configuration: &DaemonConfig) -> aap_types::Result<aap_transport::HttpsTransport> {
    use aap_types::ErrorCode;
    use base64::Engine;
    let encoded = &configuration.upstream_roots_der_base64;
    if encoded.len() > 64 || (!configuration.profiles.is_empty() && encoded.is_empty()) {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let mut roots = Vec::new();
    for value in encoded {
        if value.len() > 90_000 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let der = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| ErrorCode::RequestInvalid)?;
        if der.len() > 65_536 || base64::engine::general_purpose::STANDARD.encode(&der) != *value {
            return Err(ErrorCode::RequestInvalid.into());
        }
        roots.push(rustls::pki_types::CertificateDer::from(der));
    }
    aap_transport::HttpsTransport::new(roots)
}

#[cfg(target_os = "linux")]
pub mod runtime;
