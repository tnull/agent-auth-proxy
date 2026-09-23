use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::SocketAddr,
    path::PathBuf,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub session: PathBuf,
    pub request: Option<aap_types::ExecuteRequest>,
    #[serde(default)]
    pub action: Option<Action>,
    pub tcp: Vec<SocketAddr>,
    pub udp: Vec<SocketAddr>,
    pub unix: Vec<PathBuf>,
    pub abstract_unix: Vec<String>,
    pub files: Vec<PathBuf>,
    pub host_pids: Vec<u32>,
    pub seeded_fds: Vec<i32>,
    pub unshare: PathBuf,
    pub descendant: bool,
}
impl Job {
    pub fn validate(&self) -> io::Result<()> {
        if self.tcp.len() > 8
            || self.udp.len() > 8
            || self.unix.len() > 8
            || self.abstract_unix.len() > 8
            || self.files.len() > 8
            || self.host_pids.len() > 8
            || self.seeded_fds.len() > 8
            || self.seeded_fds.iter().any(|fd| *fd < 3)
            || (self.request.is_some() && self.action.is_some())
        {
            return Err(io::Error::other("probe bounds"));
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub tcp: Vec<bool>,
    pub udp: Vec<bool>,
    pub unix: Vec<bool>,
    pub abstract_unix: Vec<bool>,
    pub files: Vec<bool>,
    pub file_writes: Vec<bool>,
    pub processes: Vec<bool>,
    pub inherited_fds: Vec<bool>,
    pub environment_clean: bool,
    pub no_new_privs: bool,
    pub capabilities_empty: bool,
    pub userns_denied: bool,
    pub namespaces: BTreeMap<String, String>,
    pub uid: u32,
    pub gid: u32,
    pub uid_map: String,
    pub gid_map: String,
    pub limits: BTreeMap<String, u64>,
    pub request: Option<RequestResult>,
    pub action: Option<ActionResult>,
    pub descendant: Option<Box<Report>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Mcp {
        name: String,
        arguments: serde_json::Value,
    },
    Stream {
        open: aap_types::stream::Open,
        send: Vec<u8>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResult {
    pub value: Option<serde_json::Value>,
    pub error: Option<aap_types::ErrorCode>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestResult {
    pub id: String,
    pub status: Option<u16>,
    pub body: Vec<u8>,
    pub error: Option<aap_types::ErrorCode>,
}
pub fn read<T: serde::de::DeserializeOwned>(input: &mut impl Read) -> io::Result<Option<T>> {
    let mut prefix = [0; 4];
    match input.read(&mut prefix[..1])? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!(),
    }
    input.read_exact(&mut prefix[1..])?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > 64 * 1024 {
        return Err(io::Error::other("probe frame limit"));
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    aap_types::json::decode(&bytes)
        .map(Some)
        .map_err(|_| io::Error::other("invalid probe message"))
}
pub fn write(output: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| io::Error::other("invalid report"))?;
    if bytes.len() > 64 * 1024 {
        return Err(io::Error::other("probe report limit"));
    }
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(&bytes)
}
