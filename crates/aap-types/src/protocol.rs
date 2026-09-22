//! Credential-free local wire types. Only host-bound channels establish identity.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    SessionInvalid,
    PolicyDenied,
    RequestInvalid,
    RequestConflict,
    LimitExceeded,
    InspectionUnavailable,
    AuthProfileUnsupported,
    AuthFailed,
    VaultLocked,
    VaultUnavailable,
    PlaceholderInvalid,
    AuthInProgress,
    InteractionUnavailable,
    ObservationUnavailable,
    UpstreamUnavailable,
    OutcomeUnknown,
    ResultUnavailable,
    InternalError,
}

/// Errors carry only fixed safe messages, never native store/network diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    pub code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl Error {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            request_id: None,
        }
    }
    pub fn for_request(mut self, id: &str) -> Self {
        self.request_id = Some(id.to_owned());
        self
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "proxy operation failed: {:?}", self.code)
    }
}
impl std::error::Error for Error {}
impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchItems {
    pub uri: String,
    pub query: Option<String>,
    pub cursor: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetLogin {
    pub request_id: String,
    pub item_id: String,
    pub uri: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthContext {
    pub auth_context: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub items: Vec<ItemSummary>,
    pub next_cursor: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ItemSummary {
    pub item_id: String,
    pub label: String,
    pub account_alias: String,
    pub origins: Vec<String>,
    pub login_supported: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Login {
    pub item_id: String,
    pub auth_context: String,
    pub credentials: Credentials,
    pub submission: Submission,
    pub expires_in: u64,
    pub reusable: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: CredentialValue,
    pub password: CredentialValue,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialValue {
    pub value: String,
    pub kind: CredentialKind,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Placeholder,
    Value,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Submission {
    pub uri: String,
    pub method: String,
    pub content_type: String,
    pub fields: CredentialFields,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFields {
    pub username: String,
    pub password: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthState {
    Unauthenticated,
    Authenticating,
    Authenticated,
    Expired,
    Revoked,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthStatus {
    pub item_id: String,
    pub account_alias: String,
    pub state: AuthState,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Logout {
    pub state: AuthState,
    pub remote_logout: RemoteLogout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteLogout {
    Confirmed,
    Failed,
    Unknown,
    NotSupported,
}

/// Wire bodies are base64, even if their contents happen to be UTF-8.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub request_id: String,
    pub resource: String,
    pub auth_context: Option<String>,
    pub method: String,
    pub target: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_base64: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Received,
    Validated,
    PendingApproval,
    Ready,
    Dispatching,
    Completed,
    Failed,
    OutcomeUnknown,
    Denied,
    Expired,
    Cancelled,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationStatus {
    pub request_id: String,
    pub state: OperationState,
    pub status: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_inputs_cannot_add_authority_fields() {
        assert!(
            crate::json::decode::<SearchItems>(
                br#"{"uri":"https://example.test","tenant_id":"other"}"#
            )
            .is_err(),
            "search accepted caller tenant"
        );
        assert!(crate::json::decode::<GetLogin>(br#"{"request_id":"x","item_id":"x","uri":"https://example.test","store_ref":"other"}"#).is_err());
        assert!(
            crate::json::decode::<AuthContext>(br#"{"auth_context":"x","approve":true}"#).is_err()
        );
        assert!(crate::json::decode::<ExecuteRequest>(br#"{"request_id":"x","resource":"x","method":"GET","target":"https://example.test","session_id":"other"}"#).is_err());
    }
}
