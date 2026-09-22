//! Credential-free MCP tools over the shared session interface.

use aap_types::{AgentService, Error, ErrorCode, ExecuteRequest, OperationStatus};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use rmcp::model::{CallToolResult, ErrorData, Tool};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{io::Write, sync::Arc, time::Duration};

mod schema;
mod stdio;
pub use stdio::serve;

pub const PROTOCOL_VERSION: &str = "2025-11-25";
pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_INPUT: usize = 2 * 1024 * 1024;
pub const MAX_OUTPUT: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct Tools {
    service: Arc<dyn AgentService>,
}
impl Tools {
    pub fn new(service: Arc<dyn AgentService>) -> Self {
        Self { service }
    }
    pub fn definitions() -> Vec<Tool> {
        schema::definitions()
    }
    /// Call a local tool without granting any authority beyond the supplied session.
    /// The stdio adapter additionally bounds framing, concurrency, and lifetime.
    pub async fn call(&self, name: &str, arguments: Value) -> Result<CallToolResult, ErrorData> {
        if !schema::NAMES.contains(&name) {
            return Err(ErrorData::invalid_params("unsupported tool", None));
        }
        let id = arguments
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|id| aap_types::ids::valid_id(id, 16))
            .map(str::to_owned);
        let result = match encode(&arguments, MAX_INPUT) {
            Err(error) => Err(error),
            Ok(_) => {
                match tokio::time::timeout(Duration::from_secs(600), self.dispatch(name, arguments))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => Err(ErrorCode::OutcomeUnknown.into()),
                }
            }
        };
        Ok(tool_result(result.map_err(|mut error| {
            // Never accept an implementation's unrelated request ID in this result.
            error.request_id = id;
            error
        })))
    }

    async fn dispatch(&self, name: &str, arguments: Value) -> aap_types::Result<Value> {
        match name {
            "vault.search_items" => value(self.service.search_items(parse(arguments)?).await?),
            "vault.get_login" => {
                let request: aap_types::GetLogin = parse(arguments)?;
                valid_id(&request.request_id, 16)?;
                value(self.service.get_login(request).await?)
            }
            "vault.auth_status" | "vault.logout" => {
                let request: aap_types::AuthContext = parse(arguments)?;
                valid_id(&request.auth_context, 32)?;
                if name == "vault.auth_status" {
                    value(self.service.auth_status(request).await?)
                } else {
                    value(self.service.logout(request).await?)
                }
            }
            "request.status" | "request.cancel" => {
                let request: aap_types::wire::RequestId = parse(arguments)?;
                valid_id(&request.request_id, 16)?;
                if name == "request.status" {
                    value(self.service.request_status(request.request_id).await?)
                } else {
                    value(self.service.cancel(request.request_id).await?)
                }
            }
            "request.execute" => self.execute(parse(arguments)?).await,
            _ => Err(ErrorCode::RequestInvalid.into()),
        }
    }

    async fn execute(&self, request: ExecuteRequest) -> aap_types::Result<Value> {
        valid_id(&request.request_id, 16)?;
        if let Some(context) = &request.auth_context {
            valid_id(context, 32)?;
        }
        if request.body_base64.len() > MAX_BODY.div_ceil(3) * 4
            || request.headers.len() > 64
            || request
                .headers
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>()
                > 16 * 1024
        {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let decoded = STANDARD
            .decode(&request.body_base64)
            .map_err(|_| ErrorCode::RequestInvalid)?;
        if decoded.len() > MAX_BODY {
            return Err(ErrorCode::LimitExceeded.into());
        }
        if STANDARD.encode(&decoded) != request.body_base64 {
            return Err(ErrorCode::RequestInvalid.into());
        }
        drop(decoded);
        let id = request.request_id.clone();
        let response = self.service.execute(request).await?;
        let (parts, mut body) = response.into_parts();
        let existing = match parts.headers.get("x-aap-operation-state") {
            None => false,
            Some(value)
                if value == "existing"
                    && parts
                        .headers
                        .get_all("x-aap-operation-state")
                        .iter()
                        .count()
                        == 1 =>
            {
                true
            }
            _ => return Err(ErrorCode::ResultUnavailable.into()),
        };
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if let Some(data) = frame.data_ref() {
                if data.len() > MAX_BODY.saturating_sub(bytes.len()) {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                bytes.extend_from_slice(data);
            } else {
                return Err(ErrorCode::InspectionUnavailable.into());
            }
        }
        if existing {
            let operation: OperationStatus =
                aap_types::json::decode(&bytes).map_err(|_| ErrorCode::ResultUnavailable)?;
            if operation.request_id != id || !matches!(parts.status.as_u16(), 200 | 202) {
                return Err(ErrorCode::ResultUnavailable.into());
            }
            return Ok(json!({"kind":"operation","operation":operation}));
        }
        if parts.headers.len() > 64
            || parts
                .headers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.len())
                .sum::<usize>()
                > 16 * 1024
        {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let mut headers = Vec::new();
        for (name, value) in &parts.headers {
            if name.as_str().starts_with("x-aap-")
                || matches!(
                    name.as_str(),
                    "set-cookie"
                        | "set-cookie2"
                        | "cookie"
                        | "authorization"
                        | "proxy-authorization"
                        | "proxy-authenticate"
                        | "www-authenticate"
                        | "connection"
                        | "transfer-encoding"
                        | "content-length"
                )
            {
                continue;
            }
            let value = value.to_str().map_err(|_| ErrorCode::ResultUnavailable)?;
            headers.push((name.as_str(), value));
        }
        Ok(
            json!({"kind":"response","request_id":id,"status":parts.status.as_u16(),"headers":headers,"body_base64":STANDARD.encode(bytes),"complete":true}),
        )
    }
}

fn valid_id(id: &str, bytes: usize) -> aap_types::Result<()> {
    if aap_types::ids::valid_id(id, bytes) {
        Ok(())
    } else {
        Err(ErrorCode::RequestInvalid.into())
    }
}
fn parse<T: DeserializeOwned>(arguments: Value) -> aap_types::Result<T> {
    serde_json::from_value(arguments).map_err(|_| ErrorCode::RequestInvalid.into())
}
fn value(value: impl Serialize) -> aap_types::Result<Value> {
    let bytes = encode(&value, MAX_BODY)?;
    serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InternalError.into())
}
fn tool_result(result: aap_types::Result<Value>) -> CallToolResult {
    let mut result = match result {
        Ok(value) => CallToolResult::structured(value),
        Err(error) => CallToolResult::structured_error(
            json!({"code":error.code,"request_id":error.request_id}),
        ),
    };
    // rmcp also models later protocols whose constructors add resultType.
    // This local server is explicitly pinned to the 2025-11-25 envelope.
    result.result_type = None;
    result
}

/// Bound serialization itself, not only its resulting allocation.
fn encode(value: &impl Serialize, limit: usize) -> aap_types::Result<Vec<u8>> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::ErrorKind::OutOfMemory.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| Error::new(ErrorCode::LimitExceeded))?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests;
