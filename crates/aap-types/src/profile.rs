//! Non-secret authentication profile data supplied by the trusted host.

use crate::CredentialFields;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginProfile {
    pub page: String,
    pub target: String,
    pub encoding: LoginEncoding,
    pub fields: CredentialFields,
    #[serde(default)]
    pub username_visible: bool,
    pub success: LoginSuccess,
    pub csrf: Option<CsrfProfile>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginEncoding {
    Form,
    Json,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginSuccess {
    pub status: u16,
    pub cookie_names: Vec<String>,
    /// Exact JSON pointer to an explicit application success flag.
    pub json_pointer: String,
    pub expected: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsrfProfile {
    /// JSON pointer in the enrolled login-page response. HTML/script rewriting
    /// requires a separate reviewed adapter and is not implicit.
    pub response_pointer: String,
    pub submit_field: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    OpenAiChat,
    AnthropicMessages,
    Generic,
}
/// Trusted request inspection, independent of sockets and credential custody.
pub trait RequestInspector: Send + Sync {
    fn inspect(&self, provider: ProviderKind, body: &[u8]) -> crate::Result<()>;
}
