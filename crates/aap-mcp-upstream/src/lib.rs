//! Trusted remote MCP message boundary, without transport or store access.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

mod profile;
mod request;
mod response;
mod sse;
mod wire;
pub use sse::SseDecoder;

pub const VERSION: &str = "2025-11-25";
pub const MAX_REQUEST: usize = 256 * 1024;
pub const MAX_RESPONSE: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub arguments: BTreeMap<String, Argument>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Argument {
    Text { max_length: u32 },
    Integer { minimum: i64, maximum: i64 },
}

/// Compiled operator policy. This does not grant a caller permission to use it.
pub struct Profile {
    tools: BTreeMap<String, Tool>,
    binding: Arc<()>,
}
/// A validated agent message, bound to the exact profile instance that read it.
/// Deliberately not Debug or Serialize: diagnostics must select safe fields.
pub struct Request {
    method: Method,
    id: Option<Value>,
    params: Value,
    cancellation_id: Option<Value>,
    binding: Arc<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Initialize,
    Initialized,
    Ping,
    List,
    Call,
    Cancel,
}

/// Responses are sanitized JSON. A ping is private upstream control work, not
/// an instruction to send it without the engine's current admission checks.
pub enum Message {
    Response(Vec<u8>),
    Ping(Ping),
}
pub struct Ping {
    id: Value,
}

#[cfg(test)]
mod tests;
