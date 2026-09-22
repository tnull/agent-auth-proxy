use crate::{MAX_INPUT, MAX_OUTPUT, Tools, encode, tool_result};
use aap_types::{ErrorCode, Result};
use rmcp::model::{
    CallToolRequestParams, Implementation, InitializeRequestParams, InitializeResult,
    ProtocolVersion, RequestId, ServerCapabilities,
};
use serde_json::{Value, json};
use std::{collections::HashMap, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    task::{AbortHandle, JoinSet},
    time::Instant,
};

const IO_WAIT: Duration = Duration::from_secs(10);
const MAX_RETAINED: usize = 16 * 1024 * 1024;

struct Pending {
    abort: AbortHandle,
    reservation: usize,
    control: bool,
    cancelled: bool,
}

/// Serve one credential-free MCP connection on caller-owned asynchronous I/O.
pub async fn serve<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    input: R,
    mut output: W,
    tools: Tools,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let result = run(input, &mut output, tools, &mut tasks).await;
    // Dropping an owned service call cancels its invocation, not an operation
    // guessed from a JSON-RPC ID. No detached handlers survive this connection.
    tasks.abort_all();
    let cleanup_deadline = Instant::now() + Duration::from_secs(2);
    let _ = tokio::time::timeout_at(cleanup_deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    let _ = tokio::time::timeout_at(cleanup_deadline, output.shutdown()).await;
    result
}

async fn run<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    input: R,
    output: &mut W,
    tools: Tools,
    tasks: &mut JoinSet<(RequestId, Value)>,
) -> Result<()> {
    let mut reader = Framer {
        reader: BufReader::with_capacity(8192, input),
        bytes: Vec::new(),
        deadline: None,
    };
    let mut pending: HashMap<RequestId, Pending> = HashMap::new();
    let mut initialized = false;
    let mut ready = false;
    let initialization_deadline = Instant::now() + IO_WAIT;
    loop {
        tokio::select! {
            biased;
            completed = tasks.join_next_with_id(), if !tasks.is_empty() => {
                match completed {
                    Some(Ok((_,(id,result)))) => {
                        if let Some(call) = pending.remove(&id) && !call.cancelled { send(output,&result).await?; }
                    },
                    Some(Err(error)) => {
                        let id = pending.iter().find(|(_,call)| call.abort.id() == error.id()).map(|(id,_)|id.clone());
                        if let Some(id) = id && let Some(call) = pending.remove(&id) && !call.cancelled {
                            send(output,&failure(Some(id),-32603,"tool handler unavailable")).await?;
                        }
                    },
                    None => {},
                }
            },
            _ = tokio::time::sleep_until(initialization_deadline), if !ready => return Err(ErrorCode::LimitExceeded.into()),
            frame = reader.next() => {
                let Some(frame) = frame? else { return Ok(()); };
                let size = frame.len();
                let message:Value = match parse_frame(&frame) {
                    Ok(value) => value,
                    Err(_) => { send(output,&failure(None,-32700,"invalid MCP message")).await?; continue; },
                };
                drop(frame);
                let Some(object) = message.as_object() else { send(output,&failure(None,-32600,"invalid MCP request")).await?; continue; };
                if object.get("jsonrpc") != Some(&json!("2.0")) || object.keys().any(|key| !["jsonrpc","id","method","params"].contains(&key.as_str())) {
                    send(output,&failure(None,-32600,"invalid MCP request")).await?; continue;
                }
                let id = match object.get("id") {
                    None => None,
                    Some(value) => match id(value) { Some(id) => Some(id), None => { send(output,&failure(None,-32600,"invalid request ID")).await?; continue; } },
                };
                let Some(method) = object.get("method").and_then(Value::as_str).filter(|method| method.len() <= 128) else {
                    send(output,&failure(id,-32600,"invalid MCP method")).await?; continue;
                };
                let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
                let Some(id) = id else {
                    if method == "notifications/initialized" && initialized && params.is_object() { ready = true; }
                    if method == "notifications/cancelled" && ready
                        && let Some(cancelled) = params.get("requestId").and_then(self::id)
                        && let Some(call) = pending.get_mut(&cancelled) { call.cancelled = true; call.abort.abort(); }
                    continue;
                };
                if pending.contains_key(&id) {
                    send(output,&failure(None,-32600,"duplicate in-flight request ID")).await?;
                    return Err(ErrorCode::RequestConflict.into());
                }
                if method == "initialize" && !initialized {
                    if serde_json::from_value::<InitializeRequestParams>(params).is_err() {
                        send(output,&failure(Some(id),-32602,"invalid initialization")).await?; continue;
                    }
                    let mut capabilities = ServerCapabilities::default();
                    capabilities.tools = Some(Default::default());
                    let result = InitializeResult::new(capabilities)
                        .with_protocol_version(ProtocolVersion::V_2025_11_25)
                        .with_server_info(Implementation::new("agent-auth-proxy", env!("CARGO_PKG_VERSION")));
                    send(output,&json!({"jsonrpc":"2.0","id":id,"result":result})).await?;
                    initialized = true;
                    continue;
                }
                if !ready {
                    send(output,&failure(Some(id),-32000,"initialization required")).await?; continue;
                }
                match method {
                    "ping" => { send(output,&json!({"jsonrpc":"2.0","id":id,"result":{}})).await?; },
                    "tools/list" => {
                        if !params.is_object() || params.as_object().is_some_and(|object| object.keys().any(|key| !["cursor","_meta"].contains(&key.as_str())))
                            || params.get("cursor").is_some_and(|cursor| !cursor.is_null()) {
                            send(output,&failure(Some(id),-32602,"invalid tool-list parameters")).await?; continue;
                        }
                        send(output,&json!({"jsonrpc":"2.0","id":id,"result":{"tools":Tools::definitions()}})).await?;
                    },
                    "tools/call" => {
                        // Reject later SDK extensions instead of silently enabling a
                        // capability excluded by the negotiated protocol/profile.
                        if !params.is_object() || params.as_object().is_some_and(|object| object.keys().any(|key| !["name","arguments","_meta"].contains(&key.as_str()))) {
                            send(output,&failure(Some(id),-32602,"invalid tool-call parameters")).await?; continue;
                        }
                        let call:CallToolRequestParams = match serde_json::from_value(params) {
                            Ok(call) => call,
                            Err(_) => { send(output,&failure(Some(id),-32602,"invalid tool-call parameters")).await?; continue; },
                        };
                        if !crate::schema::NAMES.contains(&call.name.as_ref()) {
                            send(output,&failure(Some(id),-32602,"unsupported tool")).await?; continue;
                        }
                        let control = matches!(call.name.as_ref(),"request.status"|"request.cancel");
                        let reservation = size + if control { 64*1024 } else { MAX_OUTPUT };
                        let count = pending.values().filter(|call| call.control == control).count();
                        if count >= if control {2} else {8} || tasks.len() >= 10
                            || pending.values().map(|call|call.reservation).sum::<usize>() + reservation > MAX_RETAINED - if control {0} else {128*1024} {
                            let result = tool_result(Err(ErrorCode::LimitExceeded.into()));
                            send(output,&json!({"jsonrpc":"2.0","id":id,"result":result})).await?; continue;
                        }
                        let tools = tools.clone(); let request_id = id.clone();
                        let abort = tasks.spawn(async move {
                            let result = match tools.call(&call.name,Value::Object(call.arguments.unwrap_or_default())).await {
                                Ok(result) => json!({"jsonrpc":"2.0","id":request_id,"result":result}),
                                Err(error) => json!({"jsonrpc":"2.0","id":request_id,"error":error}),
                            };
                            (request_id,result)
                        });
                        pending.insert(id,Pending { abort,reservation,control,cancelled:false });
                    },
                    _ => send(output,&failure(Some(id),-32601,"unsupported method")).await?,
                }
            }
        }
    }
}

fn id(value: &Value) -> Option<RequestId> {
    if value.as_str().is_some_and(|id| id.len() > 128) {
        return None;
    }
    serde_json::from_value(value.clone()).ok()
}
fn failure(id: Option<RequestId>, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
async fn send(output: &mut (impl AsyncWrite + Unpin), value: &Value) -> Result<()> {
    let mut bytes = encode(value, MAX_OUTPUT)?;
    bytes.push(b'\n');
    tokio::time::timeout(IO_WAIT, async {
        output.write_all(&bytes).await?;
        output.flush().await
    })
    .await
    .map_err(|_| ErrorCode::LimitExceeded)?
    .map_err(|_| ErrorCode::SessionInvalid.into())
}

struct Framer<R> {
    reader: BufReader<R>,
    bytes: Vec<u8>,
    deadline: Option<Instant>,
}
impl<R: AsyncRead + Unpin> Framer<R> {
    /// Cancellation-safe: partial bytes and their deadline survive select polls.
    async fn next(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let available = if let Some(deadline) = self.deadline {
                tokio::time::timeout_at(deadline, self.reader.fill_buf())
                    .await
                    .map_err(|_| ErrorCode::LimitExceeded)?
            } else {
                self.reader.fill_buf().await
            }
            .map_err(|_| ErrorCode::SessionInvalid)?;
            if available.is_empty() {
                return if self.bytes.is_empty() {
                    Ok(None)
                } else {
                    Err(ErrorCode::RequestInvalid.into())
                };
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.unwrap_or(available.len());
            if count > MAX_INPUT.saturating_sub(self.bytes.len()) {
                return Err(ErrorCode::LimitExceeded.into());
            }
            self.bytes.extend_from_slice(&available[..count]);
            self.reader.consume(count + usize::from(newline.is_some()));
            if newline.is_some() {
                self.deadline = None;
                return Ok(Some(std::mem::take(&mut self.bytes)));
            }
            self.deadline = Some(Instant::now() + IO_WAIT);
        }
    }
}

fn parse_frame(bytes: &[u8]) -> Result<Value> {
    // Bound structural amplification before constructing serde's Value tree.
    let (mut depth, mut structure, mut string, mut escaped) = (0usize, 0usize, false, false);
    for byte in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                string = false;
            }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    structure += 1;
                    if depth > 64 {
                        return Err(ErrorCode::LimitExceeded.into());
                    }
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                }
                b',' | b':' => structure += 1,
                _ => {}
            }
            if structure > 32768 {
                return Err(ErrorCode::LimitExceeded.into());
            }
        }
    }
    aap_types::json::decode(bytes).map_err(|_| ErrorCode::RequestInvalid.into())
}
