use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Probe {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: tokio::process::ChildStdout,
}

impl Probe {
    pub async fn spawn(executable: &Path, session: Option<&Path>) -> Self {
        let mut command = match session {
            None => tokio::process::Command::new(executable),
            Some(session) => sandbox(executable, session).await,
        };
        let mut child = command
            .env_clear()
            .env("AAP_SYNTHETIC_PRIVATE_ENV", "synthetic-environment-canary")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Self {
            input: child.stdin.take().unwrap(),
            output: child.stdout.take().unwrap(),
            child,
        }
    }
    pub async fn job(&mut self, value: &Value) -> Value {
        tokio::time::timeout(Duration::from_secs(15), async {
            let bytes = serde_json::to_vec(value).unwrap();
            assert!(bytes.len() <= 64 * 1024);
            self.input.write_u32(bytes.len() as u32).await.unwrap();
            self.input.write_all(&bytes).await.unwrap();
            self.input.flush().await.unwrap();
            let length = self
                .output
                .read_u32()
                .await
                .expect("probe exited before report");
            assert!(length <= 64 * 1024);
            let mut bytes = vec![0; length as usize];
            self.output.read_exact(&mut bytes).await.unwrap();
            let report = aap_types::json::decode(&bytes).expect("invalid probe report");
            assert_report_shape(&report, value, value["descendant"] == true);
            report
        })
        .await
        .expect("probe exceeded its wall-clock budget")
    }
    pub async fn finish(mut self) {
        drop(self.input);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), self.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        let mut extra = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), self.output.read(&mut extra))
                .await
                .unwrap()
                .unwrap(),
            0,
            "unexpected report bytes"
        );
    }
}

fn assert_report_shape(report: &Value, job: &Value, descendant: bool) {
    for (field, input) in [
        ("tcp", "tcp"),
        ("udp", "udp"),
        ("unix", "unix"),
        ("abstract_unix", "abstract_unix"),
        ("files", "files"),
        ("file_writes", "files"),
        ("processes", "host_pids"),
        ("inherited_fds", "seeded_fds"),
    ] {
        assert_eq!(
            report[field].as_array().unwrap().len(),
            job[input].as_array().unwrap().len(),
            "missing {field} probe results"
        );
    }
    if descendant {
        assert!(
            report["descendant"].is_object(),
            "descendant probes are required"
        );
        assert_report_shape(&report["descendant"], job, false);
        assert!(report["descendant"]["request"].is_null());
    } else {
        assert!(report["descendant"].is_null());
    }
}

async fn sandbox(executable: &Path, session: &Path) -> tokio::process::Command {
    // This controlled harness owns every deliberately inherited descriptor.
    // It refuses an unknown inheritable descriptor instead of relying on
    // Bubblewrap to close it (Bubblewrap preserves the application's FDs).
    audit_descriptors();
    let mut command = tokio::process::Command::new("/usr/bin/prlimit");
    command.args([
        "--cpu=10:10",
        "--as=1073741824:1073741824",
        "--nproc=512:512",
        "--nofile=128:128",
        "--fsize=1048576:1048576",
        "--core=0:0",
        "--",
        "/usr/bin/bwrap",
        "--unshare-user",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--hostname",
        "aap-fixture",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        "16777216",
        "--tmpfs",
        "/tmp",
        "--chdir",
        "/tmp",
    ]);
    for file in runtime_files(executable).await {
        command.arg("--ro-bind").arg(&file).arg(&file);
    }
    command
        .arg("--ro-bind")
        .arg(executable)
        .arg("/probe")
        .arg("--ro-bind")
        .arg(session)
        .arg("/session.sock")
        .args(["--remount-ro", "/", "--", "/probe"]);
    command
}

fn audit_descriptors() {
    for entry in std::fs::read_dir("/proc/self/fdinfo").unwrap() {
        let entry = entry.unwrap();
        let fd: i32 = entry.file_name().to_str().unwrap().parse().unwrap();
        if fd <= 2 {
            continue;
        }
        let info = match std::fs::read_to_string(entry.path()) {
            Ok(info) => info,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("cannot audit descriptor {fd}: {error}"),
        };
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .unwrap();
        let flags = u32::from_str_radix(flags.trim(), 8).unwrap();
        assert_ne!(
            flags & rustix::fs::OFlags::CLOEXEC.bits(),
            0,
            "unapproved inheritable descriptor {fd}"
        );
    }
}

async fn runtime_files(executable: &Path) -> BTreeSet<PathBuf> {
    let mut files = BTreeSet::from([
        PathBuf::from("/usr/bin/unshare"),
        PathBuf::from("/usr/bin/true"),
    ]);
    // Only inspect this workspace-built, trusted probe and fixed OS helpers.
    // Mount individual loader/library files, never a host /usr or home tree.
    for program in [
        executable,
        Path::new("/usr/bin/unshare"),
        Path::new("/usr/bin/true"),
    ] {
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("/usr/bin/ldd")
                .env_clear()
                .arg(program)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "cannot discover the probe's runtime files"
        );
        assert!(output.stdout.len() <= 16 * 1024);
        let text = std::str::from_utf8(&output.stdout).unwrap();
        assert!(!text.contains("not found"), "missing runtime library");
        let mut found = false;
        for word in text.split_whitespace().filter(|word| word.starts_with('/')) {
            let path = PathBuf::from(word);
            assert!(path.is_file());
            files.insert(path);
            found = true;
        }
        assert!(
            found,
            "this fixture requires dynamically linked Linux executables"
        );
    }
    files
}
