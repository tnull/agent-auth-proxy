use crate::{Profile, Tool};
use aap_types::{Result, mcp::validate_tools};
use serde_json::Value;
use std::sync::Arc;

pub(crate) use aap_types::mcp::valid_name as name;

impl Profile {
    /// Compile finite, reviewed tool policy without granting caller authority.
    pub fn new(tools: Vec<Tool>) -> Result<Self> {
        validate_tools(&tools)?;
        Ok(Self {
            tools: tools
                .into_iter()
                .map(|tool| (tool.name.clone(), tool))
                .collect(),
            binding: Arc::new(()),
        })
    }
    pub fn definitions(&self) -> Vec<Value> {
        self.tools.values().map(Tool::definition).collect()
    }
}
