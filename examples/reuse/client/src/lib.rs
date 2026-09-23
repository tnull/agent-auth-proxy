//! Credential-free external consumer; trusted setup exists only in tests.
#[path = "../../support/scenarios.rs"]
pub mod scenarios;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub sessions: [std::path::PathBuf; 2],
    pub origin: String,
}
