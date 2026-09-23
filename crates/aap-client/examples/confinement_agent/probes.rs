use super::protocol::{Job, Report};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::{TcpStream, UdpSocket},
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixStream},
    },
    process::{Command, Stdio},
    time::Duration,
};

pub fn inherited() -> io::Result<BTreeSet<i32>> {
    std::fs::read_dir("/proc/self/fd")?
        .map(|entry| {
            entry?
                .file_name()
                .to_string_lossy()
                .parse()
                .map_err(|_| io::Error::other("invalid descriptor"))
        })
        .collect()
}
pub fn run(job: &Job, inherited: &BTreeSet<i32>) -> io::Result<Report> {
    let timeout = Duration::from_millis(150);
    let tcp = job
        .tcp
        .iter()
        .map(|address| {
            TcpStream::connect_timeout(address, timeout).is_ok_and(|mut stream| {
                let _ = stream.set_write_timeout(Some(timeout));
                let _ = stream.write_all(b"probe");
                true
            })
        })
        .collect();
    let udp = job
        .udp
        .iter()
        .map(|address| {
            let local = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            UdpSocket::bind(local).is_ok_and(|socket| {
                let _ = socket.set_read_timeout(Some(timeout));
                socket.send_to(b"probe", address).is_ok() && socket.recv_from(&mut [0; 16]).is_ok()
            })
        })
        .collect();
    let unix = job
        .unix
        .iter()
        .map(|path| UnixStream::connect(path).is_ok())
        .collect();
    let abstract_unix = job
        .abstract_unix
        .iter()
        .map(|name| {
            SocketAddr::from_abstract_name(name.as_bytes())
                .is_ok_and(|address| UnixStream::connect_addr(&address).is_ok())
        })
        .collect();
    let files = job
        .files
        .iter()
        .map(|path| File::open(path).is_ok_and(|mut file| file.read(&mut [0]).is_ok()))
        .collect();
    let file_writes = job
        .files
        .iter()
        .map(|path| OpenOptions::new().write(true).open(path).is_ok())
        .collect();
    let processes = job
        .host_pids
        .iter()
        .map(|pid| {
            let pidfd = rustix::process::Pid::from_raw(*pid as i32).is_some_and(|pid| {
                rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).is_ok()
            });
            pidfd
                || File::open(format!("/proc/{pid}/environ")).is_ok()
                || std::fs::read_link(format!("/proc/{pid}/root")).is_ok()
        })
        .collect();
    let inherited_fds = job
        .seeded_fds
        .iter()
        .map(|fd| inherited.contains(fd))
        .collect();
    let status = std::fs::read_to_string("/proc/self/status")?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let no_new_privs = field("NoNewPrivs:") == Some("1");
    let capabilities_empty = ["CapEff:", "CapPrm:", "CapBnd:", "CapAmb:"]
        .iter()
        .all(|name| field(name).is_some_and(|value| u64::from_str_radix(value, 16) == Ok(0)));
    let mut namespaces = BTreeMap::new();
    for name in ["net", "mnt", "pid", "user", "ipc", "uts"] {
        namespaces.insert(
            name.to_owned(),
            std::fs::read_link(format!("/proc/self/ns/{name}"))?
                .to_string_lossy()
                .into_owned(),
        );
    }
    let mut limits = BTreeMap::new();
    for (name, resource) in [
        ("nofile", rustix::process::Resource::Nofile),
        ("processes", rustix::process::Resource::Nproc),
        ("memory", rustix::process::Resource::As),
        ("cpu", rustix::process::Resource::Cpu),
        ("file_size", rustix::process::Resource::Fsize),
        ("core", rustix::process::Resource::Core),
    ] {
        limits.insert(
            name.to_owned(),
            rustix::process::getrlimit(resource)
                .maximum
                .unwrap_or(u64::MAX),
        );
    }
    if !Command::new(&job.unshare)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        return Err(io::Error::other("namespace probe helper unavailable"));
    }
    let userns_status = Command::new(&job.unshare)
        .args(["--user", "--map-root-user", "--", "/usr/bin/true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    let userns_denied = userns_status.code() == Some(1);
    if !userns_status.success() && !userns_denied {
        return Err(io::Error::other("namespace probe did not execute"));
    }
    Ok(Report {
        tcp,
        udp,
        unix,
        abstract_unix,
        files,
        file_writes,
        processes,
        inherited_fds,
        environment_clean: std::env::vars_os().all(|(key, _)| key == "PWD"),
        no_new_privs,
        capabilities_empty,
        userns_denied,
        namespaces,
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        uid_map: std::fs::read_to_string("/proc/self/uid_map")?,
        gid_map: std::fs::read_to_string("/proc/self/gid_map")?,
        limits,
        request: None,
        action: None,
        descendant: None,
    })
}
