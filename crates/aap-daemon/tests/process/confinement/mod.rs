//! Opt-in OS acceptance test, not part of the portable broker API.
mod boundary;
mod canaries;
mod connect;
mod connect_website;
mod launcher;
mod remote_mcp;
mod tcp;
mod website;

// The opt-in fixtures deliberately change inheritance of synthetic FDs.
// Serialize those fixtures within this test process.
static LAUNCH_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use super::*;
use launcher::Probe;
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd, OwnedFd},
};

fn seed(fd: impl AsFd, output: &mut Vec<OwnedFd>) {
    let owned = rustix::io::fcntl_dupfd_cloexec(fd, 100 + output.len() as i32).unwrap();
    rustix::io::fcntl_setfd(&owned, rustix::io::FdFlags::empty()).unwrap();
    output.push(owned);
}

fn assert_flags(report: &Value, expected: bool) {
    for name in [
        "tcp",
        "udp",
        "unix",
        "abstract_unix",
        "files",
        "file_writes",
        "processes",
        "inherited_fds",
    ] {
        let flags = report[name].as_array().unwrap();
        assert!(!flags.is_empty());
        for (index, flag) in flags.iter().enumerate() {
            assert_eq!(
                flag, expected,
                "{name}[{index}] violated the expected reachability"
            );
        }
    }
    if !report["descendant"].is_null() {
        assert_flags(&report["descendant"], expected);
    }
}

fn assert_isolated(report: &Value, positive: &Value) {
    assert_flags(report, false);
    for name in [
        "environment_clean",
        "no_new_privs",
        "capabilities_empty",
        "userns_denied",
    ] {
        assert_eq!(report[name], true, "missing isolation property: {name}");
    }
    for name in ["net", "mnt", "pid", "user", "ipc", "uts"] {
        assert_ne!(
            report["namespaces"][name], positive["namespaces"][name],
            "shared {name} namespace"
        );
    }
    for (name, value) in [
        ("nofile", 128u64),
        ("processes", 512),
        ("memory", 1024 * 1024 * 1024),
        ("cpu", 10),
        ("file_size", 1024 * 1024),
        ("core", 0),
    ] {
        assert_eq!(report["limits"][name], value, "missing {name} ceiling");
    }
    assert_eq!(report["uid"], positive["uid"]);
    assert_eq!(report["gid"], positive["gid"]);
    if !report["descendant"].is_null() {
        assert_isolated(&report["descendant"], &positive["descendant"]);
    }
}

async fn attachment(fixture: &Fixture, control: &std::path::Path) -> (SessionAttachment, PathBuf) {
    let (status, value) = local(
        control.to_owned(),
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":120}),
    )
    .await;
    assert!(status.is_success());
    let attachment: SessionAttachment = serde_json::from_value(value).unwrap();
    let path = fixture.root.join("r").join(&attachment.ingress_socket);
    (attachment, path)
}

#[tokio::test]
#[ignore = "requires Linux namespaces, Bubblewrap, prlimit, and a built AAP_CONFINEMENT_AGENT; see docs/confinement.md"]
async fn confined_agent_uses_only_its_session_attachment() {
    let _exclusive = LAUNCH_TEST_LOCK.lock().await;
    let executable = PathBuf::from(
        std::env::var_os("AAP_CONFINEMENT_AGENT")
            .expect("build and explicitly select the confinement-agent example"),
    );
    assert!(executable.is_absolute() && executable.is_file());
    let fixture = Fixture::new().await;
    let canaries = canaries::Canaries::new(&fixture.root).await;
    let (mut daemon, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(&ready.control_socket);
    let observer = fixture.root.join("r").join(&ready.observation_socket);
    let (session, session_path) = attachment(&fixture, &control).await;
    let (_, other_session) = attachment(&fixture, &control).await;
    let files = [
        fixture.root.join("c/catalog.json"),
        fixture.root.join("c/daemon.json"),
        fixture.root.join("s/vault.sqlite3"),
    ];
    let mut inherited = vec![];
    seed(
        std::net::TcpStream::connect(canaries.tcp[0]).unwrap(),
        &mut inherited,
    );
    seed(
        std::os::unix::net::UnixStream::connect(&control).unwrap(),
        &mut inherited,
    );
    seed(File::open(&files[0]).unwrap(), &mut inherited);
    seed(File::open(fixture.root.join("r")).unwrap(), &mut inherited);
    seed(File::open("/proc/self/ns/net").unwrap(), &mut inherited);
    let mut job = json!({
        "session":session_path,"request":null,
        "tcp":canaries.tcp,"udp":canaries.udp,
        "unix":[canaries.unix, control, observer, other_session],
        "abstract_unix":[canaries.abstract_unix],"files":files,
        "host_pids":[std::process::id(),daemon.id().unwrap()],
        "seeded_fds":inherited.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(),
        "unshare":"/usr/bin/unshare","descendant":true
    });
    let mut positive_probe = Probe::spawn(&executable, None).await;
    let positive = positive_probe.job(&job).await;
    assert_flags(&positive, true);
    assert_eq!(positive["environment_clean"], false);
    assert_eq!(
        positive["userns_denied"], false,
        "host must support the positive user-namespace control"
    );
    positive_probe.finish().await;
    let baseline = canaries.positive_baseline().await;
    for fd in &inherited {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC).unwrap();
    }

    let mut confined = Probe::spawn(&executable, Some(&session_path)).await;
    job["session"] = json!("/session.sock");
    let request = fixture.request();
    job["request"] = serde_json::to_value(&request).unwrap();
    let report = confined.job(&job).await;
    assert_isolated(&report, &positive);
    eprintln!(
        "confined identity: uid={}, gid={}, uid_map={}, gid_map={}",
        report["uid"], report["gid"], report["uid_map"], report["gid_map"]
    );
    assert_eq!(report["request"]["status"], 200);
    assert_eq!(
        report["request"]["body"],
        json!(b"data: [redacted]\n\n".to_vec())
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert_eq!(
        fixture.origin.requests.lock().unwrap()[0].headers["authorization"],
        "Bearer synthetic-daemon-key"
    );
    assert_eq!(
        canaries.snapshot(),
        baseline,
        "confined probe reached a host listener"
    );
    let (status, batch) = local(observer, "/aap/observe/v1/read", json!({"limit":128})).await;
    assert!(status.is_success());
    let batch: aap_observe::Batch = serde_json::from_value(batch).unwrap();
    assert!(
        batch
            .records
            .iter()
            .any(|record| record.event.request_id.as_deref() == Some(&request.request_id))
    );
    for record in &batch.records {
        if let aap_observe::Data::ContentChunk { body_base64, .. } = &record.event.data {
            assert!(
                !String::from_utf8_lossy(&STANDARD.decode(body_base64).unwrap())
                    .contains("synthetic-daemon-key")
            );
        }
    }
    assert_eq!(
        batch
            .records
            .iter()
            .filter(|record| {
                record.event.request_id.as_deref() == Some(&request.request_id)
                    && matches!(
                        record.event.data,
                        aap_observe::Data::FlowClose { complete: true, .. }
                    )
            })
            .count(),
        2,
        "both observed views must close completely"
    );
    assert!(
        local(
            control.clone(),
            "/aap/operator/v1/session/revoke",
            json!({"session_id":session.session_id})
        )
        .await
        .0
        .is_success()
    );
    job["request"] = serde_json::to_value(fixture.request()).unwrap();
    let denied = confined.job(&job).await;
    assert_isolated(&denied, &positive);
    assert!(denied["request"]["status"].is_null());
    assert!(!denied["request"]["error"].is_null());
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    confined.finish().await;

    // A separately admitted, live attachment distinguishes crash behavior
    // from the already-revoked session above. The process remains confined
    // across both daemon loss and a new daemon epoch.
    let (_, live_path) = attachment(&fixture, &control).await;
    let mut across_restart = Probe::spawn(&executable, Some(&live_path)).await;
    job["request"] = serde_json::to_value(fixture.request()).unwrap();
    let report = across_restart.job(&job).await;
    assert_isolated(&report, &positive);
    assert_eq!(report["request"]["status"], 200);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    daemon.kill().await.unwrap();
    assert!(!daemon.wait().await.unwrap().success());
    job["request"] = serde_json::to_value(fixture.request()).unwrap();
    let report = across_restart.job(&job).await;
    assert_isolated(&report, &positive);
    assert!(report["request"]["status"].is_null());
    assert!(!report["request"]["error"].is_null());
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);

    let (mut restarted, restarted_ready) = fixture.start().await;
    assert_ne!(restarted_ready.daemon_epoch, ready.daemon_epoch);
    let new_control = fixture.root.join("r").join(restarted_ready.control_socket);
    let (fresh_session, fresh_path) = attachment(&fixture, &new_control).await;
    // These processes and paths are real and accessible to the trusted host.
    File::open(format!("/proc/{}/environ", restarted.id().unwrap())).unwrap();
    job["host_pids"][1] = json!(restarted.id().unwrap());
    job["unix"][1] = json!(new_control);
    job["unix"][2] = json!(
        fixture
            .root
            .join("r")
            .join(restarted_ready.observation_socket)
    );
    job["unix"][3] = json!(fresh_path);
    for path in job["unix"].as_array().unwrap().iter().skip(1) {
        std::os::unix::net::UnixStream::connect(path.as_str().unwrap()).unwrap();
    }
    job["request"] = serde_json::to_value(fixture.request()).unwrap();
    let report = across_restart.job(&job).await;
    assert_isolated(&report, &positive);
    assert!(report["request"]["status"].is_null());
    assert!(!report["request"]["error"].is_null());
    assert_eq!(
        fixture.origin.requests.lock().unwrap().len(),
        2,
        "restart resurrected the old attachment"
    );
    across_restart.finish().await;

    let mut fresh = Probe::spawn(&executable, Some(&fresh_path)).await;
    job["request"] = serde_json::to_value(fixture.request()).unwrap();
    let report = fresh.job(&job).await;
    assert_isolated(&report, &positive);
    assert_eq!(
        report["request"]["status"], 200,
        "new epoch requires a fresh trusted attachment"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);

    let (status, collector) = local(new_control.clone(), "/aap/operator/v1/observation/create", json!({
        "scope":{"sessions":[fresh_session.session_id],"views":["agent","upstream"],"classes":["metadata"]},
        "limits":{"max_events":1,"max_bytes":8192},"lifetime_seconds":120
    })).await;
    assert!(status.is_success());
    job["request"] = serde_json::to_value(fixture.request()).unwrap();
    let report = fresh.job(&job).await;
    assert_isolated(&report, &positive);
    assert_eq!(
        report["request"]["error"],
        json!(ErrorCode::ObservationUnavailable)
    );
    assert_eq!(report["request"]["body"], json!([]));
    assert_eq!(
        fixture.origin.requests.lock().unwrap().len(),
        3,
        "required recording failure allowed dispatch"
    );
    assert!(
        local(
            new_control.clone(),
            "/aap/operator/v1/observation/revoke",
            json!({"subscription_id":collector["subscription_id"]})
        )
        .await
        .0
        .is_success()
    );
    job["request"] = serde_json::to_value(fixture.request()).unwrap();
    let report = fresh.job(&job).await;
    assert_isolated(&report, &positive);
    assert_eq!(report["request"]["status"], 200);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 4);
    fresh.finish().await;

    let (status, value) = local(
        new_control,
        "/aap/operator/v1/session/create",
        json!({
            "resources":["provider"],"lifetime_seconds":120,"require_approval":true
        }),
    )
    .await;
    assert!(status.is_success());
    let approval_session: SessionAttachment = serde_json::from_value(value).unwrap();
    let approval_path = fixture.root.join("r").join(approval_session.ingress_socket);
    let mut approval = Probe::spawn(&executable, Some(&approval_path)).await;
    job["request"] = serde_json::to_value(fixture.request()).unwrap();
    let report = approval.job(&job).await;
    assert_isolated(&report, &positive);
    assert_eq!(
        report["request"]["error"],
        json!(ErrorCode::InteractionUnavailable)
    );
    assert_eq!(report["request"]["body"], json!([]));
    assert_eq!(
        fixture.origin.requests.lock().unwrap().len(),
        4,
        "missing approval allowed dispatch"
    );
    approval.finish().await;
    stop(&mut restarted).await;
    assert_eq!(canaries.snapshot(), baseline);
}
