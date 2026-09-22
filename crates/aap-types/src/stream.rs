//! Credential-free, bounded local TCP stream binding. This module never dials.

use crate::{ErrorCode, OperationState, OperationStatus, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

mod decoder;
mod frame;
mod sequence;
pub use decoder::Decoder;
pub use sequence::Sequence;

pub const PROTOCOL: &str = "aap-stream/1";
pub const OPEN_PATH: &str = "/aap/v1/stream/open";
pub const MAX_CONTROL_BYTES: usize = 16 * 1024;
pub const MAX_DATA_BYTES: usize = 32 * 1024;
pub const MAX_DIRECTION_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_DATA_FRAMES: u32 = 65_536;
pub const MAX_APPROVAL_MS: u64 = 300_000;
pub const MAX_IDLE_MS: u64 = 60_000;
pub const MAX_LIFETIME_MS: u64 = 600_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    pub request_id: String,
    pub resource: String,
}

impl Open {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let operation: Self = decode_control(bytes)?;
        operation.validate()?;
        Ok(operation)
    }
    pub fn validate(&self) -> Result<()> {
        validate_binding(&self.request_id, &self.resource)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub request_id: String,
    pub expires_in_ms: u64,
}

impl Pending {
    pub fn validate(&self) -> Result<()> {
        if !crate::ids::valid_id(&self.request_id, 16)
            || self.expires_in_ms == 0
            || self.expires_in_ms > MAX_APPROVAL_MS
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Inspection {
    PlaintextBytes,
    Opaque,
    MetadataOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    BestEffort,
    Required,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opened {
    pub request_id: String,
    pub resource: String,
    pub max_data_bytes: u32,
    pub send_limit: u64,
    pub receive_limit: u64,
    pub idle_timeout_ms: u64,
    pub remaining_lifetime_ms: u64,
    pub inspection: Inspection,
    pub observation: Observation,
}

impl Opened {
    pub fn validate(&self) -> Result<()> {
        validate_binding(&self.request_id, &self.resource)?;
        if self.max_data_bytes == 0
            || self.max_data_bytes as usize > MAX_DATA_BYTES
            || self.send_limit == 0
            || self.send_limit > MAX_DIRECTION_BYTES
            || self.receive_limit == 0
            || self.receive_limit > MAX_DIRECTION_BYTES
            || self.idle_timeout_ms == 0
            || self.idle_timeout_ms > MAX_IDLE_MS
            || self.remaining_lifetime_ms == 0
            || self.remaining_lifetime_ms > MAX_LIFETIME_MS
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    OrderlyEnd,
    Cancelled,
    SessionEnded,
    PolicyChanged,
    ApprovalDenied,
    ApprovalTimeout,
    InteractionUnavailable,
    ObservationUnavailable,
    CapacityExhausted,
    UpstreamUnavailable,
    InvalidFrame,
    LimitExceeded,
    Timeout,
    AttachmentLost,
    InternalError,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terminal {
    #[serde(with = "terminal_status")]
    pub operation: OperationStatus,
    pub cause: Cause,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}

impl Terminal {
    pub fn validate(&self) -> Result<()> {
        if !crate::ids::valid_id(&self.operation.request_id, 16)
            || self.operation.status.is_some()
            || !matches!(
                self.operation.state,
                OperationState::Completed
                    | OperationState::Failed
                    | OperationState::OutcomeUnknown
                    | OperationState::Denied
                    | OperationState::Expired
                    | OperationState::Cancelled
            )
            || (self.operation.state == OperationState::Completed)
                != (self.cause == Cause::OrderlyEnd)
            || self.sent_bytes > MAX_DIRECTION_BYTES
            || self.received_bytes > MAX_DIRECTION_BYTES
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(())
    }
}

// Preserve the common OperationStatus API, but require every nested wire field
// and exactly status:null here without changing unrelated HTTP DTO decoding.
mod terminal_status {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        value: &OperationStatus,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<OperationStatus, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            request_id: String,
            state: OperationState,
            status: (),
        }
        let wire = Wire::deserialize(deserializer)?;
        let () = wire.status;
        Ok(OperationStatus {
            request_id: wire.request_id,
            state: wire.state,
            status: None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    Agent,
    Daemon,
}

impl Sender {
    fn index(self) -> usize {
        match self {
            Self::Agent => 0,
            Self::Daemon => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Pending = 1,
    Opened = 2,
    Data = 3,
    SendEnd = 4,
    Terminal = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    kind: Kind,
    length: usize,
}

impl Header {
    pub fn kind(self) -> Kind {
        self.kind
    }
    pub fn length(self) -> usize {
        self.length
    }
}

/// No implicit formatting of arbitrary application bytes.
pub enum Frame {
    Pending(Pending),
    Opened(Opened),
    Data(Bytes),
    SendEnd,
    Terminal(Terminal),
}

pub struct Encoded {
    pub header: [u8; 5],
    pub payload: Bytes,
}

fn validate_binding(request_id: &str, resource: &str) -> Result<()> {
    // Same ASCII alias grammar as the private catalog; no destination syntax.
    if !crate::ids::valid_id(request_id, 16)
        || resource.is_empty()
        || resource.len() > 64
        || !resource.as_bytes()[0].is_ascii_alphanumeric()
        || !resource
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    Ok(())
}

fn decode_control<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(ErrorCode::LimitExceeded.into());
    }
    // Bound structural amplification before the strict decoder allocates a tree.
    // Quoted/escaped delimiters do not count; syntax is checked by the decoder.
    let (mut depth, mut tokens, mut quoted, mut escaped) = (0usize, 0usize, false, false);
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    tokens += 1;
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                    tokens += 1;
                }
                b',' | b':' => tokens += 1,
                _ => {}
            }
            if depth > 8 || tokens > 128 {
                return Err(ErrorCode::LimitExceeded.into());
            }
        }
    }
    crate::json::decode(bytes).map_err(|_| ErrorCode::RequestInvalid.into())
}

#[cfg(test)]
mod tests;
