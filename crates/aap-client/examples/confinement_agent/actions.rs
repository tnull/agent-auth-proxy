use super::protocol::{self, Action, ActionResult, Job, Report};
use aap_types::{ErrorCode, Result};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

pub async fn run(action: Action, job: Job) -> ActionResult {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        match action {
            Action::Connect { request } => super::connect::run(job.session, request).await,
            Action::Mcp { name, arguments } => mcp(job, name, arguments).await,
            Action::Stream { open, send } => super::stream::run(job.session, open, send).await,
        }
    })
    .await
    .unwrap_or_else(|_| Err(ErrorCode::ResultUnavailable.into()));
    match result {
        Ok(value) => ActionResult {
            value: Some(value),
            error: None,
        },
        Err(error) => ActionResult {
            value: None,
            error: Some(error.code),
        },
    }
}

/// The tool subprocess performs its own bypass probes before starting the
/// public credential-free MCP server. No daemon/store code is linked here.
pub fn bridge() -> io::Result<()> {
    let inherited = super::probes::inherited()?;
    let job = protocol::read::<Job>(&mut io::stdin().lock())?
        .ok_or_else(|| io::Error::other("missing bridge setup"))?;
    job.validate()?;
    if job.request.is_some() || job.action.is_some() || job.descendant {
        return Err(io::Error::other("invalid bridge setup"));
    }
    let report = super::probes::run(&job, &inherited)?;
    protocol::write(&mut io::stdout().lock(), &report)?;
    io::stdout().flush()?;
    // The parent waits for the setup report before sending any MCP bytes,
    // so the blocking setup reader cannot prefetch the subsequent protocol.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let tools = aap_mcp::Tools::new(Arc::new(aap_client::DaemonSessionClient::new(job.session)));
    runtime
        .block_on(aap_mcp::serve(
            tokio::io::stdin(),
            tokio::io::stdout(),
            tools,
        ))
        .map_err(|_| io::Error::other("MCP bridge failed"))
}

async fn mcp(mut job: Job, name: String, arguments: Value) -> Result<Value> {
    let executable = std::env::current_exe().map_err(|_| ErrorCode::InternalError)?;
    let mut child = tokio::process::Command::new(executable)
        .arg("--mcp-bridge")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    let mut input = child.stdin.take().ok_or(ErrorCode::InternalError)?;
    let mut output = BufReader::new(child.stdout.take().ok_or(ErrorCode::InternalError)?);
    job.descendant = false;
    job.request = None;
    job.action = None;
    let mut setup = vec![];
    protocol::write(&mut setup, &job).map_err(|_| ErrorCode::RequestInvalid)?;
    input
        .write_all(&setup)
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    input
        .flush()
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    let length = output
        .read_u32()
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    if length > 64 * 1024 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    let mut bytes = vec![0; length as usize];
    output
        .read_exact(&mut bytes)
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    let process: Report =
        aap_types::json::decode(&bytes).map_err(|_| ErrorCode::ResultUnavailable)?;
    send(&mut input, json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"confinement-agent","version":"1"}}})).await?;
    let initialize = receive(&mut output).await?;
    if initialize["jsonrpc"] != "2.0"
        || initialize["id"] != 0
        || initialize.get("error").is_some()
        || initialize["result"]["protocolVersion"] != "2025-11-25"
    {
        return Err(ErrorCode::ResultUnavailable.into());
    }
    send(
        &mut input,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await?;
    send(&mut input, json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await?;
    let response = receive(&mut output).await?;
    if response["jsonrpc"] != "2.0"
        || response["id"] != 1
        || response.get("error").is_some()
        || !response["result"].is_object()
    {
        return Err(ErrorCode::ResultUnavailable.into());
    }
    drop(input);
    if !child
        .wait()
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?
        .success()
        || output
            .read(&mut [0])
            .await
            .map_err(|_| ErrorCode::ResultUnavailable)?
            != 0
    {
        return Err(ErrorCode::ResultUnavailable.into());
    }
    Ok(
        json!({"process":process,"tool":response["result"],"protocol_version":initialize["result"]["protocolVersion"]}),
    )
}

async fn send(output: &mut (impl tokio::io::AsyncWrite + Unpin), value: Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| ErrorCode::RequestInvalid)?;
    if bytes.len() >= 64 * 1024 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    bytes.push(b'\n');
    output
        .write_all(&bytes)
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    output
        .flush()
        .await
        .map_err(|_| ErrorCode::ResultUnavailable.into())
}
async fn receive(input: &mut (impl AsyncBufRead + Unpin)) -> Result<Value> {
    let mut bytes = vec![];
    loop {
        let available = input
            .fill_buf()
            .await
            .map_err(|_| ErrorCode::ResultUnavailable)?;
        if available.is_empty() {
            return Err(ErrorCode::ResultUnavailable.into());
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let count = end.map_or(available.len(), |index| index + 1);
        if count > (64 * 1024usize).saturating_sub(bytes.len()) {
            return Err(ErrorCode::LimitExceeded.into());
        }
        bytes.extend_from_slice(&available[..count]);
        input.consume(count);
        if end.is_some() {
            return aap_types::json::decode(&bytes)
                .map_err(|_| ErrorCode::ResultUnavailable.into());
        }
    }
}
