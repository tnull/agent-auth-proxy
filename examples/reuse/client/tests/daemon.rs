#![cfg(target_os = "linux")]
#[path = "../../support/fixture.rs"]
mod fixture;
use aap_types::{AgentService, ErrorCode, SearchItems};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

async fn local(socket: &Path, path: &str, body: Value) -> Value {
    let io = tokio::net::UnixStream::connect(socket).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri(path)
                .header("host", "aap.local")
                .header("content-type", "application/json")
                .header("connection", "close")
                .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    let bytes = Limited::new(response.into_body(), 2 * 1024 * 1024)
        .collect()
        .await
        .unwrap()
        .to_bytes();
    driver.abort();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn independent_credential_free_binary_runs_the_shared_daemon_scenarios() {
    let daemon = PathBuf::from(
        std::env::var_os("AAP_DAEMON")
            .expect("build the daemon and set AAP_DAEMON to its absolute executable path"),
    );
    assert!(daemon.is_absolute() && daemon.is_file());
    for encoding in [
        aap_types::profile::LoginEncoding::Form,
        aap_types::profile::LoginEncoding::Json,
    ] {
        tokio::time::timeout(Duration::from_secs(45), run(&daemon, encoding))
            .await
            .expect("external client fixture exceeded deadline");
    }
}
async fn run(daemon: &Path, encoding: aap_types::profile::LoginEncoding) {
    let fixture = fixture::Fixture::new(encoding).await;
    let config = json!({"schema_version":1,"configuration_revision":1,
        "store":{"alias":"default","directory":fixture.root().join("s")},"runtime_directory":fixture.root().join("r"),
        "upstream_roots_der_base64":[STANDARD.encode(fixture.origin.certificate.as_ref())],
        "static_hosts":{"fixture.test":[fixture.origin.address.ip()]},"profiles":fixture.profiles,
        "observation":{"acceptance":"local_memory","max_events":4096,"max_bytes":4*1024*1024,"required":true}});
    let private = aap_config::PrivateDir::open(&fixture.root().join("c"), false).unwrap();
    private
        .write_atomic(
            "daemon.json",
            &serde_json::to_vec(&config).unwrap(),
            1024 * 1024,
        )
        .unwrap();
    private
        .write_atomic(
            "catalog.json",
            &serde_json::to_vec(&fixture.catalog).unwrap(),
            1024 * 1024,
        )
        .unwrap();
    let mut daemon = tokio::process::Command::new(daemon)
        .arg("serve")
        .arg(fixture.root().join("c"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = daemon.stdin.take().unwrap();
    input
        .write_all(fixture::Fixture::key().expose())
        .await
        .unwrap();
    drop(input);
    let mut output = BufReader::new(daemon.stdout.take().unwrap());
    let mut line = String::new();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            (&mut output).take(8192).read_line(&mut line)
        )
        .await
        .unwrap()
        .unwrap()
            > 0
    );
    let ready: Value = serde_json::from_str(&line).unwrap();
    let control = fixture
        .root()
        .join("r")
        .join(ready["control_socket"].as_str().unwrap());
    let observer = fixture
        .root()
        .join("r")
        .join(ready["observation_socket"].as_str().unwrap());
    let mut sessions = vec![];
    for _ in 0..2 {
        sessions.push(
            local(
                &control,
                "/aap/operator/v1/session/create",
                json!({"resources":["provider","website"],"lifetime_seconds":60}),
            )
            .await,
        );
    }
    let job = reuse_client::Job {
        sessions: [0, 1].map(|index| {
            fixture
                .root()
                .join("r")
                .join(sessions[index]["ingress_socket"].as_str().unwrap())
        }),
        origin: fixture.origin.origin(),
    };
    let retained = job
        .sessions
        .clone()
        .map(aap_client::DaemonSessionClient::new);
    let mut client = tokio::process::Command::new(env!("CARGO_BIN_EXE_reuse-client"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = client.stdin.take().unwrap();
    input
        .write_all(&serde_json::to_vec(&job).unwrap())
        .await
        .unwrap();
    drop(input);
    let mut bytes = vec![];
    let mut output = client.stdout.take().unwrap();
    (&mut output)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    assert!(
        client.wait().await.unwrap().success(),
        "credential-free consumer did not complete shared scenarios"
    );
    assert!(bytes.len() <= 64 * 1024);
    assert_eq!(output.read(&mut [0]).await.unwrap(), 0);
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    let mut records = vec![];
    let mut cursor: Option<aap_observe::Cursor> = None;
    loop {
        let page = local(
            &observer,
            "/aap/observe/v1/read",
            json!({"cursor":cursor,"limit":256}),
        )
        .await;
        let batch: aap_observe::Batch = serde_json::from_value(page).unwrap();
        assert!(batch.gap.is_none());
        if batch.records.is_empty() {
            break;
        }
        assert!(records.len() < 4096);
        records.extend(batch.records);
        cursor = Some(batch.cursor);
    }
    fixture.verify(&report, &records);
    for session in sessions {
        local(
            &control,
            "/aap/operator/v1/session/revoke",
            json!({"session_id":session["session_id"]}),
        )
        .await;
    }
    for client in retained {
        assert!(matches!(client.clone().search_items(SearchItems {
            uri: format!("{}/login", fixture.origin.origin()), query: None, cursor: None,
        }).await, Err(error) if error.code == ErrorCode::SessionInvalid));
    }
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 10);
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(daemon.id().unwrap() as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), daemon.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
