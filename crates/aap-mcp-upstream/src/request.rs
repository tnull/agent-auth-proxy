use crate::{MAX_REQUEST, Method, Profile, Request, VERSION, wire};
use aap_types::{ErrorCode, Result};
use rmcp::model::{InitializeRequestParams, ProtocolVersion};
use serde_json::{Value, json};

impl Profile {
    pub fn request(&self, body: &[u8]) -> Result<Request> {
        let message = wire::decode(body, MAX_REQUEST)?;
        let object = wire::object(&message, &["jsonrpc", "id", "method", "params"])?;
        if object.get("jsonrpc") != Some(&json!("2.0"))
            || object.get("id").is_some_and(|id| !wire::valid_id(id))
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::RequestInvalid)?;
        let id = object.get("id").cloned();
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        wire::empty_meta(&params)?;
        let (method, params, cancellation_id) = match method {
            "initialize" => {
                wire::object(
                    &params,
                    &["protocolVersion", "capabilities", "clientInfo", "_meta"],
                )?;
                let init: InitializeRequestParams =
                    serde_json::from_value(params).map_err(|_| ErrorCode::RequestInvalid)?;
                if init.protocol_version != ProtocolVersion::V_2025_11_25 {
                    return Err(ErrorCode::AuthProfileUnsupported.into());
                }
                (
                    Method::Initialize,
                    json!({"protocolVersion":VERSION,"capabilities":{},"clientInfo":implementation()}),
                    None,
                )
            }
            "ping" | "notifications/initialized" | "tools/list" => {
                wire::object(&params, &["_meta"])?;
                (
                    match method {
                        "ping" => Method::Ping,
                        "tools/list" => Method::List,
                        _ => Method::Initialized,
                    },
                    json!({}),
                    None,
                )
            }
            "tools/call" => {
                wire::object(&params, &["name", "arguments", "_meta"])?;
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(ErrorCode::RequestInvalid)?;
                let tool = self.tools.get(name).ok_or(ErrorCode::PolicyDenied)?;
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if !tool.accepts(&arguments) {
                    return Err(ErrorCode::PolicyDenied.into());
                }
                (
                    Method::Call,
                    json!({"name":name,"arguments":arguments}),
                    None,
                )
            }
            "notifications/cancelled" => {
                wire::object(&params, &["requestId", "reason", "_meta"])?;
                let target = params
                    .get("requestId")
                    .filter(|id| wire::valid_id(id))
                    .ok_or(ErrorCode::RequestInvalid)?;
                if params
                    .get("reason")
                    .is_some_and(|reason| !reason.is_string())
                {
                    return Err(ErrorCode::RequestInvalid.into());
                }
                (Method::Cancel, json!({}), Some(target.clone()))
            }
            _ => return Err(ErrorCode::AuthProfileUnsupported.into()),
        };
        if id.is_none() != matches!(method, Method::Initialized | Method::Cancel) {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(Request {
            method,
            id,
            params,
            cancellation_id,
            binding: self.binding.clone(),
        })
    }
}

impl Request {
    pub fn method(&self) -> Method {
        self.method
    }
    pub fn id(&self) -> Option<&Value> {
        self.id.as_ref()
    }
    pub fn cancellation_id(&self) -> Option<&Value> {
        self.cancellation_id.as_ref()
    }

    /// Encode using an engine-assigned nonzero request ID, or a mapped target
    /// for cancellation. The caller owns uniqueness, context, and live-ID checks.
    pub fn encode(&self, mapped_id: Option<u64>) -> Result<Vec<u8>> {
        if mapped_id.is_some_and(|id| id == 0 || id > 9_007_199_254_740_991)
            || mapped_id.is_none() != (self.method == Method::Initialized)
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let method = match self.method {
            Method::Initialize => "initialize",
            Method::Initialized => "notifications/initialized",
            Method::Ping => "ping",
            Method::List => "tools/list",
            Method::Call => "tools/call",
            Method::Cancel => "notifications/cancelled",
        };
        let mut message = json!({"jsonrpc":"2.0","method":method});
        if self.id.is_some() {
            message["id"] = json!(mapped_id);
        }
        if self.method == Method::Cancel {
            message["params"] = json!({"requestId":mapped_id});
        } else if self
            .params
            .as_object()
            .is_some_and(|params| !params.is_empty())
        {
            message["params"] = self.params.clone();
        }
        wire::encode(&message, MAX_REQUEST)
    }
}

pub(crate) fn implementation() -> Value {
    json!({"name":"agent-auth-proxy","version":env!("CARGO_PKG_VERSION")})
}
