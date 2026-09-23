mod origin;
mod provision;
mod smoke;
mod wire;

use aap_daemon::{Ready, SessionAttachment};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::Ordering,
    time::Duration,
};
use tokio::io::{AsyncWriteExt, BufReader};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub daemon: PathBuf,
    pub daemon_epoch: String,
    pub origin: String,
    pub session_socket: PathBuf,
}

pub struct Demo {
    pub info: Info,
    child: tokio::process::Child,
    origin: origin::Origin,
    observer: PathBuf,
    cursor: Option<aap_observe::Cursor>,
    _state: provision::State,
}

impl Demo {
    pub async fn start(root: &Path, daemon: &Path) -> Result<Self> {
        let daemon = std::fs::canonicalize(daemon)?;
        let state = provision::open(root).await?;
        let origin = origin::Origin::start().await?;
        provision::configure(root, &origin)?;
        let mut child = tokio::process::Command::new(&daemon)
            .arg("serve")
            .arg(root.join("c"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut input = child.stdin.take().ok_or("missing daemon unlock channel")?;
        input.write_all(state.key.expose()).await?;
        drop(input);
        let ready: Ready = serde_json::from_value(
            wire::read_json(&mut BufReader::new(
                child.stdout.take().ok_or("missing daemon readiness")?,
            ))
            .await?,
        )?;
        let attachment: SessionAttachment = serde_json::from_value(
            wire::local(
                &root.join("r").join(&ready.control_socket),
                "/aap/operator/v1/session/create",
                json!({"resources":["provider","website"],"lifetime_seconds":3600}),
            )
            .await?,
        )?;
        let info = Info {
            daemon,
            daemon_epoch: ready.daemon_epoch,
            origin: origin.url(),
            session_socket: root.join("r").join(attachment.ingress_socket),
        };
        state
            .directory
            .write_atomic("demo.json", &serde_json::to_vec_pretty(&info)?, 65536)?;
        state.directory.write_atomic(
            "mcp.json",
            &serde_json::to_vec_pretty(&json!({"mcpServers":{
                "aap-demo":{"command":info.daemon,"args":["mcp-bridge",info.session_socket]}
            }}))?,
            65536,
        )?;
        let prompt = format!(
            "Use only the aap-demo MCP tools for this experiment. The resource `website` is {}.\nSearch vault.search_items with uri {}/login, then vault.get_login for item account.\nUse fresh canonical base64url request IDs (16 random bytes, no padding) for new operations.\nWith the returned auth_context, request.execute GET /login, decode body_base64, then\nPOST /session using the returned fake username, fake password and CSRF placeholder.\nThe exact form body is user=<placeholder>&password=<placeholder>&csrf=<placeholder>,\ncontent-type application/x-www-form-urlencoded; encode that body as standard base64.\nGET /protected using the same auth_context, check vault.auth_status, and vault.logout.\nNever invent credentials, retry uncertain operations, or bypass the proxy.\nThe local synthetic provider resource is `provider`, POST {}/v1/chat/completions,\nwith model demo, ordinary text messages and stream:false. No API key is supplied by you.\n",
            info.origin, info.origin, info.origin
        );
        state
            .directory
            .write_atomic("agent-prompt.txt", prompt.as_bytes(), 65536)?;
        Ok(Self {
            info,
            child,
            origin,
            observer: root.join("r").join(ready.observation_socket),
            cursor: None,
            _state: state,
        })
    }
    pub async fn smoke(&mut self) -> Result<Value> {
        let before = self.origin.receipts.load(Ordering::SeqCst);
        let mut report = smoke::run(&self.info).await?;
        if self.origin.receipts.load(Ordering::SeqCst) - before != 4 {
            return Err("unexpected demo upstream dispatch count".into());
        }
        let records = self.observe().await?;
        if records.is_empty() {
            return Err("no observable demo traffic".into());
        }
        report["observation_records"] = json!(records.len());
        Ok(report)
    }
    pub async fn observe(&mut self) -> Result<Vec<aap_observe::Record>> {
        use base64::Engine;
        let mut records = Vec::new();
        for _ in 0..16 {
            let batch: aap_observe::Batch = serde_json::from_value(
                wire::local(
                    &self.observer,
                    "/aap/observe/v1/read",
                    json!({"cursor":self.cursor,"limit":128}),
                )
                .await?,
            )?;
            if batch.gap.is_some() {
                eprintln!("Demo observation reports a gap; do not infer complete capture.");
            }
            for record in &batch.records {
                origin::clean(&serde_json::to_vec(record)?)?;
                if let aap_observe::Data::ContentChunk { body_base64, .. } = &record.event.data {
                    origin::clean(&base64::engine::general_purpose::STANDARD.decode(body_base64)?)?;
                }
            }
            wire::local(
                &self.observer,
                "/aap/observe/v1/ack",
                serde_json::to_value(&batch.cursor)?,
            )
            .await?;
            self.cursor = Some(batch.cursor);
            let empty = batch.records.is_empty();
            records.extend(batch.records);
            if empty {
                break;
            }
        }
        Ok(records)
    }
    pub async fn stop(mut self) -> Result<()> {
        wire::stop(&mut self.child).await
    }
}

pub async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 2 && args[0] == "check" {
        let directory = aap_config::PrivateDir::open(Path::new(&args[1]), false)?;
        let info: Info = directory.read_json("demo.json", 65536)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&smoke::run(&info).await?)?
        );
        return Ok(());
    }
    if args.len() != 3 || (args[0] != "serve" && args[0] != "smoke") {
        return Err("usage: demo <serve|smoke> ABSOLUTE_STATE_DIR DAEMON_BINARY; or demo check ABSOLUTE_STATE_DIR".into());
    }
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let root = Path::new(&args[1]);
    let mut demo = Demo::start(root, Path::new(&args[2])).await?;
    let result = async {
        let report = demo.smoke().await?;
        if args[0] == "smoke" {
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        eprintln!("Demo walkthrough passed. Synthetic-only; this launcher does NOT sandbox your agent.");
        eprintln!("Origin: {}\nMCP settings: {}\nAgent prompt: {}\nStop: Ctrl-C. Session expires in one hour. State is retained.",
            demo.info.origin, root.join("mcp.json").display(), root.join("agent-prompt.txt").display());
        eprintln!("Observation JSON lines stream on stdout. Startup check: {}", report);
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        let lifetime = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(lifetime);
        loop {
            tokio::select! {
                _ = term.recv() => break,
                _ = interrupt.recv() => break,
                _ = &mut lifetime => { eprintln!("Demo session expired; restart for a fresh session."); break; },
                _ = interval.tick() => {
                    if demo.child.try_wait()?.is_some() { return Err("daemon stopped unexpectedly".into()); }
                    for record in demo.observe().await? { println!("{}", serde_json::to_string(&record)?); }
                },
            }
        }
        Result::<()>::Ok(())
    }.await;
    let stopped = demo.stop().await;
    result.and(stopped)
}
