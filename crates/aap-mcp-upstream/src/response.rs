use crate::{
    MAX_RESPONSE, Message, Method, Ping, Profile, Request, VERSION, profile, request, wire,
};
use aap_auth::Redactor;
use aap_types::{ErrorCode, Result};
use rmcp::model::{CallToolResult, InitializeResult, ProtocolVersion};
use serde_json::{Map, Value, json};
use std::{collections::BTreeSet, sync::Arc};

impl Profile {
    /// Validate one complete upstream JSON message. The caller must withhold
    /// the final result until HTTP/SSE completion and all context checks pass.
    /// `redactor` must already include the credential and private session ID.
    pub fn response(
        &self,
        request: &Request,
        upstream_id: u64,
        body: &[u8],
        redactor: &Redactor,
    ) -> Result<Message> {
        self.response_inner(request, upstream_id, body, redactor)
            .map_err(|error| {
                if error.code == ErrorCode::LimitExceeded {
                    error
                } else {
                    ErrorCode::InspectionUnavailable.into()
                }
            })
    }

    fn response_inner(
        &self,
        request: &Request,
        upstream_id: u64,
        body: &[u8],
        redactor: &Redactor,
    ) -> Result<Message> {
        if !Arc::ptr_eq(&self.binding, &request.binding)
            || request.id.is_none()
            || upstream_id == 0
            || upstream_id > 9_007_199_254_740_991
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let message = wire::decode(body, MAX_RESPONSE)?;
        if message.get("method").is_some() {
            wire::object(&message, &["jsonrpc", "id", "method", "params"])?;
            if message.get("jsonrpc") != Some(&json!("2.0"))
                || message.get("method") != Some(&json!("ping"))
            {
                return Err(ErrorCode::AuthProfileUnsupported.into());
            }
            let id = message
                .get("id")
                .filter(|id| wire::valid_id(id))
                .ok_or(ErrorCode::RequestInvalid)?;
            let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
            wire::object(&params, &["_meta"])?;
            wire::empty_meta(&params)?;
            return Ok(Message::Ping(Ping {
                id: id.clone(),
                owner: None,
                used: std::sync::atomic::AtomicBool::new(false),
            }));
        }
        let object = wire::object(&message, &["jsonrpc", "id", "result", "error"])?;
        if object.get("jsonrpc") != Some(&json!("2.0"))
            || object.get("id") != Some(&json!(upstream_id))
            || object.contains_key("result") == object.contains_key("error")
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let agent_id = request.id.as_ref().ok_or(ErrorCode::RequestInvalid)?;
        let mut budget = MAX_RESPONSE;
        // A caller-controlled ID cannot become a response-secret echo channel.
        if sanitize(agent_id.clone(), redactor, &mut budget)? != *agent_id {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        let safe = if let Some(error) = object.get("error") {
            let error = wire::object(error, &["code", "message", "data"])?;
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok())
                .ok_or(ErrorCode::RequestInvalid)?;
            if !error.get("message").is_some_and(Value::is_string) {
                return Err(ErrorCode::RequestInvalid.into());
            }
            if sanitize(json!(code), redactor, &mut budget)? != json!(code) {
                return Err(ErrorCode::InspectionUnavailable.into());
            }
            json!({"jsonrpc":"2.0","id":agent_id,"error":{"code":code,"message":"upstream MCP request failed"}})
        } else {
            let result = object.get("result").ok_or(ErrorCode::RequestInvalid)?;
            let safe = match request.method {
                Method::Initialize => {
                    wire::object(
                        result,
                        &[
                            "protocolVersion",
                            "capabilities",
                            "serverInfo",
                            "instructions",
                            "_meta",
                        ],
                    )?;
                    let init: InitializeResult = serde_json::from_value(result.clone())
                        .map_err(|_| ErrorCode::RequestInvalid)?;
                    if init.protocol_version != ProtocolVersion::V_2025_11_25
                        || init.capabilities.tools.is_none()
                    {
                        return Err(ErrorCode::AuthProfileUnsupported.into());
                    }
                    json!({"protocolVersion":VERSION,"capabilities":{"tools":{}},"serverInfo":request::implementation()})
                }
                Method::Ping => {
                    wire::object(result, &["_meta"])?;
                    json!({})
                }
                Method::List => self.list(result)?,
                Method::Call => call_result(result)?,
                _ => return Err(ErrorCode::RequestInvalid.into()),
            };
            let safe = sanitize(safe, redactor, &mut budget)?;
            // A secret can coincide with a schema key or protocol literal. Do
            // not deliver malformed protocol after structurally redacting it.
            // Revalidation discards its reconstruction; the sanitized value,
            // never an original operator description, is what gets delivered.
            match request.method {
                Method::Call => {
                    call_result(&safe)?;
                }
                Method::List => {
                    self.list(&safe)?;
                }
                Method::Initialize => {
                    let init: InitializeResult = serde_json::from_value(safe.clone())
                        .map_err(|_| ErrorCode::InspectionUnavailable)?;
                    if init.protocol_version != ProtocolVersion::V_2025_11_25
                        || init.capabilities.tools.is_none()
                    {
                        return Err(ErrorCode::InspectionUnavailable.into());
                    }
                }
                Method::Ping => {
                    wire::object(&safe, &[])?;
                }
                _ => return Err(ErrorCode::InspectionUnavailable.into()),
            }
            json!({"jsonrpc":"2.0","id":agent_id,"result":safe})
        };
        Ok(Message::Response(wire::encode(&safe, MAX_RESPONSE)?))
    }

    fn list(&self, result: &Value) -> Result<Value> {
        wire::object(result, &["tools", "_meta"])?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .filter(|tools| tools.len() <= 64)
            .ok_or(ErrorCode::RequestInvalid)?;
        let mut seen = BTreeSet::new();
        for tool in tools {
            // SDK validation is subordinate to the pinned profile, not an
            // invitation to enable the SDK's later protocol extensions.
            let _: rmcp::model::Tool =
                serde_json::from_value(tool.clone()).map_err(|_| ErrorCode::RequestInvalid)?;
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| profile::name(name, 128))
                .ok_or(ErrorCode::RequestInvalid)?;
            if !seen.insert(name) {
                return Err(ErrorCode::RequestInvalid.into());
            }
            if let Some(enrolled) = self.tools.get(name)
                && (tool.get("inputSchema") != Some(&enrolled.schema())
                    || tool.get("outputSchema").is_some()
                    || tool.get("execution").is_some())
            {
                return Err(ErrorCode::AuthProfileUnsupported.into());
            }
        }
        if self.tools.keys().any(|name| !seen.contains(name.as_str())) {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        Ok(json!({"tools":self.definitions()}))
    }
}

fn call_result(result: &Value) -> Result<Value> {
    wire::object(
        result,
        &["content", "structuredContent", "isError", "_meta"],
    )?;
    let _: CallToolResult =
        serde_json::from_value(result.clone()).map_err(|_| ErrorCode::RequestInvalid)?;
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .filter(|content| content.len() <= 64)
        .ok_or(ErrorCode::RequestInvalid)?;
    let mut safe = Vec::new();
    for block in content {
        wire::object(block, &["type", "text", "annotations", "_meta"])?;
        if block.get("type") != Some(&json!("text")) {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        let text = block
            .get("text")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::RequestInvalid)?;
        safe.push(json!({"type":"text","text":text}));
    }
    let mut result_safe = json!({"content":safe});
    if let Some(structured) = result.get("structuredContent") {
        if !structured.is_object() {
            return Err(ErrorCode::RequestInvalid.into());
        }
        result_safe["structuredContent"] = structured.clone();
    }
    if let Some(error) = result.get("isError") {
        if !error.is_boolean() {
            return Err(ErrorCode::RequestInvalid.into());
        }
        result_safe["isError"] = error.clone();
    }
    Ok(result_safe)
}

impl Ping {
    /// Private outbound bytes. Do not return these to an agent or observer.
    pub fn response(&self) -> Result<Vec<u8>> {
        wire::encode(
            &json!({"jsonrpc":"2.0","id":self.id,"result":{}}),
            MAX_RESPONSE,
        )
    }
}

fn text(value: &str, template: &Redactor, budget: &mut usize) -> Result<String> {
    let mut redactor = template.fresh();
    let mut output = Vec::new();
    for chunk in value
        .as_bytes()
        .chunks(16 * 1024)
        .chain(std::iter::once(&[][..]))
    {
        let bytes = redactor.feed(chunk, chunk.is_empty())?;
        if bytes.len() > *budget {
            return Err(ErrorCode::LimitExceeded.into());
        }
        *budget -= bytes.len();
        output.extend_from_slice(&bytes);
    }
    String::from_utf8(output).map_err(|_| ErrorCode::InspectionUnavailable.into())
}

fn sanitize(value: Value, redactor: &Redactor, budget: &mut usize) -> Result<Value> {
    Ok(match value {
        Value::String(value) => Value::String(text(&value, redactor, budget)?),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| sanitize(value, redactor, budget))
                .collect::<Result<_>>()?,
        ),
        Value::Object(values) => {
            let mut safe = Map::new();
            for (key, value) in values {
                let key = text(&key, redactor, budget)?;
                let value = sanitize(value, redactor, budget)?;
                if safe.insert(key, value).is_some() {
                    return Err(ErrorCode::InspectionUnavailable.into());
                }
            }
            Value::Object(safe)
        }
        value => {
            let original = value.to_string();
            let safe = text(&original, redactor, budget)?;
            if safe == original {
                value
            } else {
                Value::String("[redacted]".into())
            }
        }
    })
}
