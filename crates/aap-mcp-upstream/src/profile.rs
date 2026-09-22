use crate::{Argument, MAX_REQUEST, Profile, Tool, wire};
use aap_types::{ErrorCode, Result};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc};

impl Profile {
    /// Compile a finite allowlist supplied by the trusted operator. Every
    /// declared argument is required; unsupported schemas are not inferred.
    pub fn new(tools: Vec<Tool>) -> Result<Self> {
        if tools.is_empty() || tools.len() > 32 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let mut compiled = BTreeMap::new();
        for tool in tools {
            if !name(&tool.name, 128)
                || tool.description.is_empty()
                || tool.description.len() > 4096
                || tool
                    .description
                    .chars()
                    .any(|c| c.is_control() && c != '\n')
                || tool.arguments.len() > 32
                || tool.arguments.iter().any(|(field, rule)| {
                    !name(field, 64)
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
            if compiled.insert(tool.name.clone(), tool).is_some() {
                return Err(ErrorCode::RequestInvalid.into());
            }
        }
        let profile = Self {
            tools: compiled,
            binding: Arc::new(()),
        };
        wire::encode(&json!(profile.definitions()), MAX_REQUEST)?;
        Ok(profile)
    }

    pub fn definitions(&self) -> Vec<Value> {
        self.tools
            .values()
            .map(|tool| {
                json!({
                    "name":tool.name,"description":tool.description,"inputSchema":tool.schema()
                })
            })
            .collect()
    }
}

impl Tool {
    pub(crate) fn schema(&self) -> Value {
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

    pub(crate) fn accepts(&self, value: &Value) -> bool {
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

pub(crate) fn name(name: &str, maximum: usize) -> bool {
    !name.is_empty()
        && name.len() <= maximum
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
