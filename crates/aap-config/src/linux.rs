use super::{Error, PrivateDir, Result};
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags},
    io::Errno,
};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::AsRawFd,
    path::{Component, Path, PathBuf},
};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::NOFOLLOW
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);
const MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;

impl PrivateDir {
    /// Open an absolute directory without traversing symlinks or untrusted writers.
    /// Only the final component may be created. Existing permissions are not repaired.
    pub fn open(path: &Path, create: bool) -> Result<Self> {
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(Error::InvalidPath);
        }
        let names: Vec<_> = components
            .map(|component| match component {
                Component::Normal(name) => Ok(name),
                _ => Err(Error::InvalidPath),
            })
            .collect::<Result<_>>()?;
        if names.is_empty() || names.len() > 64 {
            return Err(Error::InvalidPath);
        }
        let mut directory =
            File::from(fs::open("/", DIRECTORY_FLAGS, Mode::empty()).map_err(map_errno)?);
        for (index, name) in names.iter().enumerate() {
            validate_ancestor(&directory)?;
            let final_component = index + 1 == names.len();
            let child = match fs::openat(&directory, *name, DIRECTORY_FLAGS, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) if final_component && create => {
                    fs::mkdirat(&directory, *name, Mode::from_raw_mode(0o700))
                        .map_err(map_errno)?;
                    directory.sync_all().map_err(|_| Error::Unavailable)?;
                    fs::openat(&directory, *name, DIRECTORY_FLAGS, Mode::empty())
                        .map_err(map_errno)?
                }
                Err(error) => return Err(map_errno(error)),
            };
            directory = File::from(child);
        }
        validate_private(&directory, true)?;
        Ok(Self { directory })
    }

    pub fn open_file(&self, name: &str, writable: bool) -> Result<File> {
        valid_name(name)?;
        validate_private(&self.directory, true)?;
        let flags = FILE_FLAGS
            | if writable {
                OFlags::RDWR
            } else {
                OFlags::RDONLY
            };
        let file =
            File::from(fs::openat(&self.directory, name, flags, Mode::empty()).map_err(map_errno)?);
        validate_private(&file, false)?;
        Ok(file)
    }

    /// Create a new 0600 file, never truncate or follow an existing entry.
    pub fn create_file(&self, name: &str) -> Result<File> {
        valid_name(name)?;
        validate_private(&self.directory, true)?;
        let file = File::from(
            fs::openat(
                &self.directory,
                name,
                FILE_FLAGS | OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            )
            .map_err(map_errno)?,
        );
        validate_private(&file, false)?;
        Ok(file)
    }

    pub fn read(&self, name: &str, max_bytes: usize) -> Result<Vec<u8>> {
        valid_limit(max_bytes)?;
        let mut file = self.open_file(name, false)?;
        if file.metadata().map_err(|_| Error::Unavailable)?.len() > max_bytes as u64 {
            return Err(Error::TooLarge);
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        if bytes.len() > max_bytes {
            return Err(Error::TooLarge);
        }
        validate_private(&file, false)?;
        validate_private(&self.directory, true)?;
        Ok(bytes)
    }

    /// Write already validated content. A final directory-sync error is an uncertain
    /// durability outcome, not proof that the rename did not take effect.
    pub fn write_atomic(&self, name: &str, bytes: &[u8], max_bytes: usize) -> Result<()> {
        valid_name(name)?;
        valid_limit(max_bytes)?;
        if bytes.len() > max_bytes {
            return Err(Error::TooLarge);
        }
        match self.open_file(name, false) {
            Ok(_) | Err(Error::NotFound) => {}
            Err(error) => return Err(error),
        }
        let temporary = format!(
            ".aap-tmp-{}",
            aap_types::ids::random_id(16).map_err(|_| Error::Unavailable)?
        );
        let mut file = self.create_file(&temporary)?;
        let result = (|| {
            file.write_all(bytes).map_err(|_| Error::Unavailable)?;
            file.sync_all().map_err(|_| Error::Unavailable)?;
            validate_private(&file, false)?;
            validate_private(&self.directory, true)?;
            match self.open_file(name, false) {
                Ok(_) | Err(Error::NotFound) => {}
                Err(error) => return Err(error),
            }
            fs::renameat(&self.directory, temporary.as_str(), &self.directory, name)
                .map_err(map_errno)?;
            self.directory.sync_all().map_err(|_| Error::Unavailable)
        })();
        if result.is_err() {
            // Only our exclusively created temporary entry is eligible for cleanup.
            let _ = fs::unlinkat(&self.directory, temporary.as_str(), AtFlags::empty());
        }
        result
    }

    /// An anchored Linux path for a previously created private backend file.
    /// The caller must retain this directory handle and prohibit untrusted same-UID
    /// access. Native backends must also check any journals/sidecars they open.
    pub fn backend_path(&self, name: &str) -> Result<PathBuf> {
        self.open_file(name, true)?;
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.directory.as_raw_fd(),
            name
        )))
    }
}

fn valid_limit(limit: usize) -> Result<()> {
    if limit == 0 || limit > MAX_BUFFERED_BYTES {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}

fn valid_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

fn validate_ancestor(file: &File) -> Result<()> {
    let stat = fs::fstat(file).map_err(map_errno)?;
    let uid = rustix::process::geteuid().as_raw();
    let sticky_root = stat.st_uid == 0 && stat.st_mode & 0o1000 != 0;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != 0 && stat.st_uid != uid)
        || (stat.st_mode & 0o022 != 0 && !sticky_root)
    {
        return Err(Error::UnsafePermissions);
    }
    Ok(())
}

fn validate_private(file: &File, directory: bool) -> Result<()> {
    let stat = fs::fstat(file).map_err(map_errno)?;
    let (kind, mode) = if directory {
        (FileType::Directory, 0o700)
    } else {
        (FileType::RegularFile, 0o600)
    };
    if stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7777 != mode
        || FileType::from_raw_mode(stat.st_mode) != kind
        || (!directory && stat.st_nlink != 1)
    {
        return Err(Error::UnsafePermissions);
    }
    for attribute in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut buffer = [0u8; 1];
        match fs::fgetxattr(file, attribute, &mut buffer[..]) {
            Err(Errno::NODATA | Errno::NOTSUP) => {}
            Ok(_) | Err(Errno::RANGE) => return Err(Error::UnsafePermissions),
            Err(_) => return Err(Error::Unavailable),
        }
    }
    Ok(())
}

fn map_errno(error: Errno) -> Error {
    match error {
        Errno::NOENT => Error::NotFound,
        Errno::LOOP | Errno::NOTDIR | Errno::ACCESS | Errno::PERM => Error::UnsafePermissions,
        _ => Error::Unavailable,
    }
}
