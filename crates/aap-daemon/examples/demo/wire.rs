use super::{Result, origin};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

pub async fn read_json(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Value> {
    let mut line = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        reader.take(1024 * 1024 + 1).read_until(b'\n', &mut line),
    )
    .await??;
    if line.len() > 1024 * 1024 || !line.ends_with(b"\n") {
        return Err("demo child closed or exceeded its response bound".into());
    }
    Ok(serde_json::from_slice(&line)?)
}

struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn local(socket: &Path, path: &str, input: Value) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let stream = tokio::net::UnixStream::connect(socket).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "aap.local")
            .header("content-type", "application/json")
            .header("connection", "close")
            .body(Full::new(Bytes::from(serde_json::to_vec(&input)?)))?;
        let response = sender.send_request(request).await?;
        if response.status() != 200 {
            return Err("demo local request was refused".into());
        }
        let body = Limited::new(response.into_body(), 1024 * 1024)
            .collect()
            .await?
            .to_bytes();
        Ok(serde_json::from_slice(&body)?)
    })
    .await?
}

pub async fn stop(child: &mut tokio::process::Child) -> Result<()> {
    if child.try_wait()?.is_none() {
        let pid = child
            .id()
            .and_then(|id| rustix::process::Pid::from_raw(id as i32))
            .ok_or("missing child pid")?;
        match rustix::process::kill_process(pid, rustix::process::Signal::TERM) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => return Err(error.into()),
        }
    }
    match tokio::time::timeout(Duration::from_secs(6), child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(_) => Err("demo child exited unsuccessfully".into()),
        Err(_) => {
            child.kill().await?;
            Err("demo child exceeded shutdown deadline and was killed".into())
        }
    }
}

pub struct Mcp {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: BufReader<tokio::process::ChildStdout>,
    next: u64,
}
impl Mcp {
    pub async fn start(daemon: &Path, socket: &Path) -> Result<Self> {
        let mut child = tokio::process::Command::new(daemon)
            .arg("mcp-bridge")
            .arg(socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut peer = Self {
            input: child.stdin.take().ok_or("missing MCP input")?,
            output: BufReader::new(child.stdout.take().ok_or("missing MCP output")?),
            child,
            next: 1,
        };
        let result = peer.rpc("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"aap-demo","version":"1"}})).await?;
        if result["protocolVersion"] != "2025-11-25" {
            return Err("unexpected MCP protocol".into());
        }
        peer.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await?;
        let tools = peer.rpc("tools/list", json!({})).await?;
        if tools["tools"].as_array().map(Vec::len) != Some(7) {
            return Err("missing MCP tools".into());
        }
        Ok(peer)
    }
    async fn send(&mut self, value: Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        tokio::time::timeout(Duration::from_secs(10), self.input.write_all(&bytes)).await??;
        Ok(())
    }
    async fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next;
        self.next += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await?;
        let response = read_json(&mut self.output).await?;
        origin::clean(&serde_json::to_vec(&response)?)?;
        if response["id"] != id
            || response.get("error").is_some()
            || response.get("result").is_none()
        {
            return Err("unexpected MCP reply".into());
        }
        Ok(response["result"].clone())
    }
    pub async fn tool(&mut self, name: &str, args: Value) -> Result<Value> {
        self.rpc("tools/call", json!({"name":name,"arguments":args}))
            .await
    }
    pub async fn success(&mut self, name: &str, args: Value) -> Result<Value> {
        let response = self.tool(name, args).await?;
        if response["isError"] == true || response.get("structuredContent").is_none() {
            return Err("demo MCP tool was refused".into());
        }
        Ok(response["structuredContent"].clone())
    }
    pub async fn close(mut self) -> Result<()> {
        drop(self.input);
        match tokio::time::timeout(Duration::from_secs(6), self.child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(_) => Err("MCP bridge exited unsuccessfully".into()),
            Err(_) => {
                self.child.kill().await?;
                Err("MCP bridge failed to exit".into())
            }
        }
    }
}
