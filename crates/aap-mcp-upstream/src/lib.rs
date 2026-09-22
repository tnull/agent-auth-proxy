//! Trusted remote MCP message/session boundary, without transport or store access.
pub use aap_types::mcp::{Argument, MAX_REQUEST, MAX_RESPONSE, Tool, VERSION};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

mod context;
mod profile;
mod request;
mod response;
mod sse;
mod wire;
pub use context::{
    Completion, Context, Exchange, Outgoing, ResponseDecoder, SafeResponse, State,
    validate_control_ack,
};
pub use sse::SseDecoder;

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
    owner: Option<Arc<()>>,
    used: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
mod tests;
