use super::*;
use std::net::SocketAddr;

/// Trusted test-side ownership; nothing here is mounted in the agent sandbox.
pub struct Boundary {
    pub executable: PathBuf,
    pub control: PathBuf,
    pub observer: PathBuf,
    pub sessions: Vec<SessionAttachment>,
    pub paths: Vec<PathBuf>,
    pub job: Value,
    positive: Value,
    canaries: canaries::Canaries,
    baseline: Vec<usize>,
    _inherited: Vec<OwnedFd>,
}

impl Boundary {
    pub async fn new(
        fixture: &Fixture,
        daemon: &tokio::process::Child,
        ready: &Ready,
        scope: Value,
        extra_tcp: &[SocketAddr],
    ) -> Self {
        let executable = PathBuf::from(
            std::env::var_os("AAP_CONFINEMENT_AGENT")
                .expect("build and select the confinement-agent example"),
        );
        assert!(executable.is_absolute() && executable.is_file());
        let canaries = canaries::Canaries::new(&fixture.root).await;
        let control = fixture.root.join("r").join(&ready.control_socket);
        let observer = fixture.root.join("r").join(&ready.observation_socket);
        let mut sessions = vec![];
        let mut paths = vec![];
        for _ in 0..2 {
            let (status, value) = local(
                control.clone(),
                "/aap/operator/v1/session/create",
                scope.clone(),
            )
            .await;
            assert!(status.is_success());
            let session: SessionAttachment = serde_json::from_value(value).unwrap();
            paths.push(fixture.root.join("r").join(&session.ingress_socket));
            sessions.push(session);
        }
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
        let mut tcp = canaries.tcp.clone();
        tcp.extend_from_slice(extra_tcp);
        let mut job = json!({
            "session":paths[0],"request":null,"action":null,
            "tcp":tcp,"udp":canaries.udp,
            "unix":[canaries.unix,control,observer,paths[1]],
            "abstract_unix":[canaries.abstract_unix],"files":files,
            "host_pids":[std::process::id(),daemon.id().unwrap()],
            "seeded_fds":inherited.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(),
            "unshare":"/usr/bin/unshare","descendant":true
        });
        let mut process = Probe::spawn(&executable, None).await;
        let positive = process.job(&job).await;
        assert_flags(&positive, true);
        assert_eq!(positive["environment_clean"], false);
        assert_eq!(positive["userns_denied"], false);
        process.finish().await;
        let baseline = canaries.positive_baseline().await;
        for fd in &inherited {
            rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC).unwrap();
        }
        job["session"] = json!("/session.sock");
        Self {
            executable,
            control,
            observer,
            sessions,
            paths,
            job,
            positive,
            canaries,
            baseline,
            _inherited: inherited,
        }
    }
    pub async fn spawn(&self, session: usize) -> Probe {
        Probe::spawn(&self.executable, Some(&self.paths[session])).await
    }
    pub async fn action(&self, probe: &mut Probe, session: usize, action: Value) -> Value {
        let result = self.action_result(probe, session, action).await;
        assert!(
            result["error"].is_null(),
            "confined action failed: {}",
            result["error"]
        );
        assert!(result["value"].is_object());
        result["value"].clone()
    }
    pub async fn action_result(&self, probe: &mut Probe, session: usize, action: Value) -> Value {
        let mut job = self.job.clone();
        job["unix"][3] = json!(self.paths[1 - session]);
        job["action"] = action;
        let report = probe.job(&job).await;
        assert_isolated(&report, &self.positive);
        assert!(report["request"].is_null());
        assert!(report["descendant"]["action"].is_null());
        self.assert_no_bypass();
        if job["action"]["kind"] == "mcp" {
            assert_eq!(report["action"]["value"]["protocol_version"], "2025-11-25");
            assert!(
                report["action"]["value"]["process"].is_object(),
                "MCP subprocess must run its own probes"
            );
            assert_isolated(
                &report["action"]["value"]["process"],
                &self.positive["descendant"],
            );
            launcher::assert_report_shape(&report["action"]["value"]["process"], &job, false);
            assert!(report["action"]["value"]["process"]["request"].is_null());
            assert!(report["action"]["value"]["process"]["action"].is_null());
        }
        report["action"].clone()
    }
    pub fn assert_no_bypass(&self) {
        assert_eq!(
            self.canaries.snapshot(),
            self.baseline,
            "confined process reached a host canary"
        );
    }
    pub async fn tiny_collector(&self, session: usize) -> Value {
        let (status, attachment) = local(self.control.clone(), "/aap/operator/v1/observation/create", json!({
            "scope":{"sessions":[self.sessions[session].session_id],"views":["agent","upstream"],"classes":["metadata"]},
            "limits":{"max_events":1,"max_bytes":8192},"lifetime_seconds":120
        })).await;
        assert!(status.is_success());
        attachment
    }
    pub async fn remove_collector(&self, collector: Value) {
        assert!(
            local(
                self.control.clone(),
                "/aap/operator/v1/observation/revoke",
                json!({"subscription_id":collector["subscription_id"]})
            )
            .await
            .0
            .is_success()
        );
    }
    pub async fn approval_process(&self, fixture: &Fixture, resources: &[&str]) -> Probe {
        let (status, session) = local(
            self.control.clone(),
            "/aap/operator/v1/session/create",
            json!({"resources":resources,"lifetime_seconds":120,"require_approval":true}),
        )
        .await;
        assert!(status.is_success());
        let session: SessionAttachment = serde_json::from_value(session).unwrap();
        Probe::spawn(
            &self.executable,
            Some(&fixture.root.join("r").join(session.ingress_socket)),
        )
        .await
    }
    pub async fn observations(&self) -> (Vec<aap_observe::Record>, Vec<aap_observe::Gap>) {
        let mut cursor: Option<aap_observe::Cursor> = None;
        let mut records = vec![];
        let mut gaps = vec![];
        for _ in 0..16 {
            let (status, page) = local(
                self.observer.clone(),
                "/aap/observe/v1/read",
                json!({"cursor":cursor,"limit":256}),
            )
            .await;
            assert!(status.is_success());
            let page: aap_observe::Batch = serde_json::from_value(page).unwrap();
            if page.records.is_empty() && page.gap.is_none() {
                return (records, gaps);
            }
            if let Some(previous) = &cursor {
                assert_eq!(page.cursor.epoch, previous.epoch);
                assert!(
                    page.cursor.after > previous.after,
                    "observation cursor stopped advancing"
                );
            }
            records.extend(page.records);
            gaps.extend(page.gap);
            cursor = Some(page.cursor);
        }
        panic!("fixture observation-page budget exceeded");
    }
}
