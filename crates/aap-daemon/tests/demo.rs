#![cfg(target_os = "linux")]

#[allow(dead_code)]
#[path = "../examples/demo/mod.rs"]
mod demo;

use demo::Demo;
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let parent = std::env::var_os("AAP_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self(parent.join(format!("demo-{}", aap_types::ids::random_id(4).unwrap())))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

#[tokio::test]
async fn demo_bootstraps_real_mcp_and_reopens_the_same_encrypted_store() {
    let state = Directory::new();
    let daemon = std::path::Path::new(env!("CARGO_BIN_EXE_agent-auth-proxy"));
    let mut first = Demo::start(&state.0, daemon)
        .await
        .expect("demo failed to bootstrap");
    assert!(
        Demo::start(&state.0, daemon).await.is_err(),
        "second demo admitted"
    );
    let report = first.smoke().await.expect("MCP walkthrough failed");
    assert_eq!(report["provider_key_injected"], true);
    assert_eq!(report["website_authenticated"], true);
    assert_eq!(report["protected_data"], "demo protected resource");
    assert_eq!(report["logout_denied_reuse"], true);
    assert!(report["observation_records"].as_u64().unwrap() > 0);
    let root = aap_config::PrivateDir::open(&state.0, false).unwrap();
    let key = root.read("demo-unlock.key", 32).unwrap();
    assert_eq!(key.len(), 32);
    let old_info: serde_json::Value = root.read_json("demo.json", 65536).unwrap();
    first.stop().await.unwrap();
    assert!(!PathBuf::from(old_info["session_socket"].as_str().unwrap()).exists());
    let encrypted = std::fs::read(state.0.join("s/vault.sqlite3")).unwrap();
    assert!(!encrypted.starts_with(b"SQLite format 3"));
    for name in [
        "demo-unlock.key",
        "demo.json",
        "mcp.json",
        "c/daemon.json",
        "c/catalog.json",
        "s/vault.sqlite3",
    ] {
        assert_eq!(
            std::fs::metadata(state.0.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
    let mut second = Demo::start(&state.0, daemon).await.unwrap();
    assert_eq!(root.read("demo-unlock.key", 32).unwrap(), key);
    let new_info: serde_json::Value = root.read_json("demo.json", 65536).unwrap();
    assert_ne!(old_info["daemon_epoch"], new_info["daemon_epoch"]);
    assert_ne!(old_info["session_socket"], new_info["session_socket"]);
    assert_eq!(second.smoke().await.unwrap()["website_authenticated"], true);
    second.stop().await.unwrap();
    // Opening and using existing items must not reprovision/rotate their values.
    assert_eq!(
        std::fs::read(state.0.join("s/vault.sqlite3")).unwrap(),
        encrypted
    );
    // A previously valid demo must not repair an exposed unlock file on restart.
    let key_path = state.0.join("demo-unlock.key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = match Demo::start(&state.0, daemon).await {
        Ok(_) => panic!("unsafe demo unlock key was admitted"),
        Err(error) => error,
    };
    assert_eq!(
        error.downcast_ref::<aap_config::Error>(),
        Some(&aap_config::Error::UnsafePermissions)
    );
    assert_eq!(
        std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    assert_eq!(std::fs::read(&key_path).unwrap(), key);
    assert_eq!(
        std::fs::read(state.0.join("s/vault.sqlite3")).unwrap(),
        encrypted
    );
}

#[tokio::test]
async fn demo_refuses_unknown_state_without_modifying_it() {
    let state = Directory::new();
    let root = aap_config::PrivateDir::open(&state.0, true).unwrap();
    root.write_atomic("keep.txt", b"unrelated data", 64)
        .unwrap();
    let daemon = std::path::Path::new(env!("CARGO_BIN_EXE_agent-auth-proxy"));
    assert!(Demo::start(&state.0, daemon).await.is_err());
    assert_eq!(root.read("keep.txt", 64).unwrap(), b"unrelated data");
    assert_eq!(std::fs::read_dir(&state.0).unwrap().count(), 1);
}
