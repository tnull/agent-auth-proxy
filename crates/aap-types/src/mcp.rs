//! Reviewed, non-secret remote tool contracts. No MCP SDK or transport types.
use crate::{ErrorCode, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: &str = "2025-11-25";
pub const MAX_REQUEST: usize = 256 * 1024;
pub const MAX_RESPONSE: usize = 1024 * 1024;
pub const CLEANUP_HEADER: &str = "x-aap-remote-cleanup";

/// Safe local metadata: closing local authority does not prove remote rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOutcome {
    Confirmed,
    NotSupported,
    Skipped,
    Unknown,
}
impl CleanupOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::NotSupported => "not_supported",
            Self::Skipped => "skipped",
            Self::Unknown => "unknown",
        }
    }
    pub fn from_header(value: &str) -> Option<Self> {
        match value {
            "confirmed" => Some(Self::Confirmed),
            "not_supported" => Some(Self::NotSupported),
            "skipped" => Some(Self::Skipped),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

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

/// Shared enrollment validation for configuration and the protocol adapter.
/// All fields are required and extra arguments are forbidden.
pub fn validate_tools(tools: &[Tool]) -> Result<()> {
    if tools.is_empty() || tools.len() > 32 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    let mut names = BTreeSet::new();
    for tool in tools {
        if !valid_name(&tool.name, 128)
            || !names.insert(&tool.name)
            || tool.description.is_empty()
            || tool.description.len() > 4096
            || tool
                .description
                .chars()
                .any(|c| c.is_control() && c != '\n')
            || tool.arguments.len() > 32
            || tool.arguments.iter().any(|(field, rule)| {
                !valid_name(field, 64)
                    || match rule {
                        Argument::Text { max_length } => {
                            *max_length == 0 || *max_length > MAX_REQUEST as u32
                        }
                        Argument::Integer { minimum, maximum } => minimum > maximum,
                    }
            })
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
    }
    // Count escaped output without allocating an oversized serialized buffer.
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::ErrorKind::FileTooLarge.into());
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let definitions: Vec<_> = tools.iter().map(Tool::definition).collect();
    serde_json::to_writer(&mut Budget(MAX_REQUEST), &definitions)
        .map_err(|_| ErrorCode::LimitExceeded.into())
}

impl Tool {
    /// Reconstruct only the enrolled schema; validate enrollment before use.
    pub fn definition(&self) -> Value {
        json!({"name":self.name,"description":self.description,"inputSchema":self.schema()})
    }
    pub fn schema(&self) -> Value {
        let properties: Map<String, Value> = self
            .arguments
            .iter()
            .map(|(name, rule)| {
                let schema = match rule {
                    Argument::Text { max_length } => {
                        json!({"type":"string","maxLength":max_length})
                    }
                    Argument::Integer { minimum, maximum } => {
                        json!({"type":"integer","minimum":minimum,"maximum":maximum})
                    }
                };
                (name.clone(), schema)
            })
            .collect();
        json!({"type":"object","properties":properties,"required":self.arguments.keys().collect::<Vec<_>>(),"additionalProperties":false})
    }
    pub fn accepts(&self, value: &Value) -> bool {
        let Some(arguments) = value.as_object() else {
            return false;
        };
        arguments.len() == self.arguments.len()
            && self.arguments.iter().all(|(name, rule)| {
                let Some(value) = arguments.get(name) else {
                    return false;
                };
                match rule {
                    Argument::Text { max_length } => value
                        .as_str()
                        .is_some_and(|text| text.chars().count() <= *max_length as usize),
                    Argument::Integer { minimum, maximum } => value
                        .as_i64()
                        .is_some_and(|number| (*minimum..=*maximum).contains(&number)),
                }
            })
    }
}

pub fn valid_name(name: &str, maximum: usize) -> bool {
    !name.is_empty()
        && name.len() <= maximum
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
