//! Versioned local session HTTP binding, never an operator control protocol.
use serde::{Deserialize, Serialize};

pub const HOST: &str = "aap.local";
pub const EXECUTE: &str = "/aap/v1/request/execute";
pub const STATUS: &str = "/aap/v1/request/status";
pub const CANCEL: &str = "/aap/v1/request/cancel";
pub const SEARCH: &str = "/aap/v1/vault/search_items";
pub const LOGIN: &str = "/aap/v1/vault/get_login";
pub const AUTH_STATUS: &str = "/aap/v1/vault/auth_status";
pub const LOGOUT: &str = "/aap/v1/vault/logout";
pub const ADMIT_CONNECT: &str = "/aap/v1/connect/admit";
pub const ERROR_HEADER: &str = "x-aap-error";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestId {
    pub request_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectAuthority {
    pub authority: String,
}
