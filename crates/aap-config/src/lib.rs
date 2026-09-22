//! Bounded private files for trusted configuration and backend composition.

use std::fs::File;

#[cfg(target_os = "linux")]
mod linux;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPath,
    UnsafePermissions,
    NotFound,
    TooLarge,
    InvalidData,
    Unavailable,
    Unsupported,
}
pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "private file operation failed: {self:?}")
    }
}
impl std::error::Error for Error {}

pub struct PrivateDir {
    directory: File,
}

impl PrivateDir {
    pub fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
        max_bytes: usize,
    ) -> Result<T> {
        aap_types::json::decode(&self.read(name, max_bytes)?).map_err(|_| Error::InvalidData)
    }
}

#[cfg(not(target_os = "linux"))]
impl PrivateDir {
    pub fn open(_path: &std::path::Path, _create: bool) -> Result<Self> {
        Err(Error::Unsupported)
    }
    pub fn read(&self, _name: &str, _max_bytes: usize) -> Result<Vec<u8>> {
        Err(Error::Unsupported)
    }
    pub fn create_file(&self, _name: &str) -> Result<File> {
        Err(Error::Unsupported)
    }
    pub fn open_file(&self, _name: &str, _writable: bool) -> Result<File> {
        Err(Error::Unsupported)
    }
    pub fn write_atomic(&self, _name: &str, _bytes: &[u8], _max_bytes: usize) -> Result<()> {
        Err(Error::Unsupported)
    }
    pub fn backend_path(&self, _name: &str) -> Result<std::path::PathBuf> {
        Err(Error::Unsupported)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::Path,
    };

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::var_os("AAP_TEST_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                .join(format!(
                    "aap-config-tests-{}",
                    aap_types::ids::random_id(16).unwrap()
                ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn private_round_trip_and_atomic_replacement() {
        let root = Fixture::new();
        let directory = PrivateDir::open(&root.0, false).expect("private directory rejected");
        directory
            .write_atomic("catalog.json", br#"{"revision":1}"#, 1024)
            .unwrap();
        assert_eq!(
            directory.read("catalog.json", 1024).unwrap(),
            br#"{"revision":1}"#
        );
        assert_eq!(
            fs::metadata(root.0.join("catalog.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        directory
            .write_atomic("catalog.json", br#"{"revision":2}"#, 1024)
            .unwrap();
        assert_eq!(
            directory.read("catalog.json", 1024).unwrap(),
            br#"{"revision":2}"#
        );
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }

    #[test]
    fn unsafe_files_links_and_paths_fail_without_repair() {
        let root = Fixture::new();
        let directory = PrivateDir::open(&root.0, false).expect("private directory rejected");
        directory
            .write_atomic("catalog.json", b"original", 1024)
            .unwrap();
        fs::set_permissions(
            root.0.join("catalog.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(directory.read("catalog.json", 1024).is_err());
        assert!(
            directory
                .write_atomic("catalog.json", b"replaced", 1024)
                .is_err()
        );
        assert_eq!(fs::read(root.0.join("catalog.json")).unwrap(), b"original");
        assert_eq!(
            fs::metadata(root.0.join("catalog.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
        fs::set_permissions(
            root.0.join("catalog.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        symlink("catalog.json", root.0.join("link.json")).unwrap();
        assert!(directory.read("link.json", 1024).is_err());
        assert!(
            directory
                .write_atomic("link.json", b"replaced", 1024)
                .is_err()
        );
        fs::hard_link(root.0.join("catalog.json"), root.0.join("hard.json")).unwrap();
        assert!(directory.read("catalog.json", 1024).is_err());
        for name in ["../catalog.json", "/etc/passwd", "..", ".", "bad/name"] {
            assert!(directory.create_file(name).is_err());
            assert!(directory.read(name, 1024).is_err());
        }
    }

    #[test]
    fn unsafe_directories_and_oversize_reads_are_rejected() {
        let root = Fixture::new();
        let directory = PrivateDir::open(&root.0.join("private"), true)
            .expect("private directory creation failed");
        directory
            .write_atomic("large.json", b"0123456789", 1024)
            .unwrap();
        assert_eq!(
            directory.read("large.json", 5).unwrap_err(),
            Error::TooLarge
        );
        assert!(
            directory
                .write_atomic("large.json", b"replacement", 5)
                .is_err()
        );
        assert_eq!(directory.read("large.json", 1024).unwrap(), b"0123456789");
        symlink("private", root.0.join("linked")).unwrap();
        assert!(PrivateDir::open(&root.0.join("linked"), false).is_err());
        assert!(PrivateDir::open(&root.0.join("linked/subdir"), true).is_err());
        fs::set_permissions(root.0.join("private"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(PrivateDir::open(&root.0.join("private"), false).is_err());
        assert!(directory.read("large.json", 1024).is_err());
        assert!(PrivateDir::open(Path::new("relative"), false).is_err());
    }

    #[test]
    fn extended_acls_are_checked_even_when_mode_bits_are_private() {
        let root = Fixture::new();
        let directory = PrivateDir::open(&root.0, false).unwrap();
        let file = directory.create_file("catalog.json").unwrap();
        // Linux POSIX ACL v2: a named user masked to no access. The mode stays
        // 0600, so rejecting this exercises ACL inspection rather than mode bits.
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permission, uid) in [
            (1u16, 6u16, u32::MAX),
            // Use a mapped UID even in a one-user namespace. Named ACL entries
            // are rejected regardless of which identity they name.
            (2, 4, rustix::process::geteuid().as_raw()),
            (4, 0, u32::MAX),
            (16, 0, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(permission.to_le_bytes());
            acl.extend(uid.to_le_bytes());
        }
        rustix::fs::fsetxattr(
            &file,
            "system.posix_acl_access",
            &acl,
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            file.metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(
            directory.read("catalog.json", 1024).unwrap_err(),
            Error::UnsafePermissions
        );
    }

    #[test]
    fn directory_handles_stay_anchored_and_parents_cannot_be_writable() {
        let root = Fixture::new();
        let directory = PrivateDir::open(&root.0.join("private"), true).unwrap();
        directory
            .write_atomic("data.db", b"synthetic", 1024)
            .unwrap();
        let path = directory.backend_path("data.db").unwrap();
        fs::rename(root.0.join("private"), root.0.join("moved")).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"synthetic");
        assert_eq!(directory.read("data.db", 1024).unwrap(), b"synthetic");
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(PrivateDir::open(&root.0.join("moved"), false).is_err());
    }

    #[test]
    fn private_json_rejects_duplicate_members() {
        let root = Fixture::new();
        let directory = PrivateDir::open(&root.0, false).unwrap();
        directory
            .write_atomic("catalog.json", br#"{"revision":1,"revision":2}"#, 1024)
            .unwrap();
        assert!(
            directory
                .read_json::<std::collections::HashMap<String, u64>>("catalog.json", 1024)
                .is_err()
        );
        directory
            .write_atomic("catalog.json", br#"{"revision":2}"#, 1024)
            .unwrap();
        assert_eq!(
            directory
                .read_json::<std::collections::HashMap<String, u64>>("catalog.json", 1024)
                .unwrap()["revision"],
            2
        );
    }
}
