//! Encrypted credential custody, isolated from the portable store interface.

use aap_config::PrivateDir;
use aap_secrets::{
    Availability, Field, ItemMetadata, ItemRef, Lease, Result, SecretBytes, SecretFields,
    SecretStore, SecretStoreAdmin, Snapshot, StoreError, StoreStatus, Version,
};
use aap_types::BoxFuture;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

const DATABASE: &str = "vault.sqlite3";
const APPLICATION_ID: i64 = 0x4141_5031;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    Create,
    Existing,
}

pub struct SqliteStore {
    state: Arc<Mutex<State>>,
    budget: Arc<tokio::sync::Semaphore>,
    runtime: tokio::runtime::Handle,
}

struct State {
    directory: Arc<PrivateDir>,
    connection: Option<Connection>,
    identity: Option<(u64, u64)>,
    generation: Version,
}

impl SqliteStore {
    pub async fn backup(&self, destination: Arc<PrivateDir>, key: SecretBytes) -> Result<()> {
        self.run(move |state| {
            let key = raw_key(&key)?;
            let connection = state.connection.take().ok_or(StoreError::Locked)?;
            backup_connection(&connection, &destination, &key)?;
            state.connection = Some(connection);
            Ok(())
        })
        .await
    }

    /// Rotate only after a coherent encrypted recovery copy has been synchronized.
    /// Any failure after detaching the live handle leaves this instance locked.
    pub async fn rotate_key(
        &self,
        new_key: SecretBytes,
        recovery: Arc<PrivateDir>,
        recovery_key: SecretBytes,
    ) -> Result<()> {
        self.run(move |state| {
            let new_key = raw_key(&new_key)?;
            let recovery_key = raw_key(&recovery_key)?;
            let generation = Version::fresh()?;
            let connection = state.connection.take().ok_or(StoreError::Locked)?;
            backup_connection(&connection, &recovery, &recovery_key)?;
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(db_error)?;
            let mode: String = connection
                .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
                .map_err(db_error)?;
            if mode != "delete" {
                return Err(StoreError::Unavailable);
            }
            connection
                .pragma_update(None, "rekey", new_key)
                .map_err(db_error)?;
            let integrity: String = connection
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .map_err(db_error)?;
            if integrity != "ok" {
                return Err(StoreError::InvalidData);
            }
            let mode: String = connection
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
                .map_err(db_error)?;
            if mode != "wal" {
                return Err(StoreError::Unavailable);
            }
            state
                .directory
                .sync()
                .map_err(|_| StoreError::Unavailable)?;
            state.generation = generation;
            state.connection = Some(connection);
            Ok(())
        })
        .await
    }
    pub async fn open(
        directory: Arc<PrivateDir>,
        key: SecretBytes,
        mode: OpenMode,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self> {
        let store = Self {
            state: Arc::new(Mutex::new(State {
                directory,
                connection: None,
                identity: None,
                generation: Version::fresh()?,
            })),
            budget: Arc::new(tokio::sync::Semaphore::new(8)),
            runtime,
        };
        store
            .run(move |state| {
                state.connection = Some(connect(&state.directory, &key, mode)?);
                state.identity = Some(backing_identity(&state.directory)?);
                Ok(())
            })
            .await?;
        Ok(store)
    }
    pub async fn lock(&self) -> Result<()> {
        self.run(|state| {
            state.connection.take();
            state.identity = None;
            state.generation = Version::fresh()?;
            Ok(())
        })
        .await
    }
    pub async fn unlock(&self, key: SecretBytes) -> Result<()> {
        self.run(move |state| {
            if state.connection.is_some() {
                return Err(StoreError::Changed);
            }
            let generation = Version::fresh()?;
            let connection = connect(&state.directory, &key, OpenMode::Existing)?;
            let identity = backing_identity(&state.directory)?;
            state.generation = generation;
            state.identity = Some(identity);
            state.connection = Some(connection);
            Ok(())
        })
        .await
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut State) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = self
            .budget
            .clone()
            .try_acquire_owned()
            .map_err(|_| StoreError::Unavailable)?;
        let state = self.state.clone();
        self.runtime
            .spawn_blocking(move || {
                let _permit = permit;
                let mut state = state.lock().map_err(|_| StoreError::Unavailable)?;
                if state.connection.is_some()
                    && backing_identity(&state.directory).ok() != state.identity
                {
                    state.connection.take();
                    state.identity = None;
                    return Err(StoreError::Unavailable);
                }
                work(&mut state)
            })
            .await
            .map_err(|_| StoreError::Unavailable)?
    }
}

impl SecretStore for SqliteStore {
    fn status(&self) -> BoxFuture<'_, Result<StoreStatus>> {
        Box::pin(self.run(|state| {
            Ok(StoreStatus {
                availability: if state.connection.is_some() {
                    Availability::Ready
                } else {
                    Availability::Locked
                },
                generation: state.generation.clone(),
            })
        }))
    }
    fn metadata<'a>(&'a self, item: &'a ItemRef) -> BoxFuture<'a, Result<ItemMetadata>> {
        let item = item.clone();
        Box::pin(self.run(move |state| {
            let tx = state
                .connection
                .as_mut()
                .ok_or(StoreError::Locked)?
                .transaction()
                .map_err(db_error)?;
            let metadata = read_metadata(&tx, &item, &state.generation)?;
            tx.commit().map_err(db_error)?;
            Ok(metadata)
        }))
    }
    fn resolve<'a>(
        &'a self,
        item: &'a ItemRef,
        expected: &'a Lease,
    ) -> BoxFuture<'a, Result<Snapshot>> {
        let (item, expected) = (item.clone(), expected.clone());
        Box::pin(self.run(move |state| {
            let tx = state
                .connection
                .as_mut()
                .ok_or(StoreError::Locked)?
                .transaction()
                .map_err(db_error)?;
            let metadata = read_metadata(&tx, &item, &state.generation)?;
            check_lease(&metadata, &expected)?;
            let mut fields = BTreeMap::new();
            {
                let mut statement = tx
                    .prepare("SELECT kind, value FROM fields WHERE item_id = ?1 ORDER BY kind")
                    .map_err(db_error)?;
                let mut rows = statement.query([item.expose()]).map_err(db_error)?;
                while let Some(row) = rows.next().map_err(db_error)? {
                    let kind = Field::parse(&row.get::<_, String>(0).map_err(db_error)?)?;
                    let value = SecretBytes::new(row.get(1).map_err(db_error)?)?;
                    fields.insert(kind, value);
                }
            }
            tx.commit().map_err(db_error)?;
            Snapshot::new(metadata, fields)
        }))
    }
    fn revalidate<'a>(
        &'a self,
        item: &'a ItemRef,
        expected: &'a Lease,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { check_lease(&self.metadata(item).await?, expected) })
    }
}

impl SecretStoreAdmin for SqliteStore {
    fn put<'a>(
        &'a self,
        item: &'a ItemRef,
        fields: SecretFields,
        expected: Option<&'a Lease>,
    ) -> BoxFuture<'a, Result<ItemMetadata>> {
        let (item, expected) = (item.clone(), expected.cloned());
        Box::pin(self.run(move |state| {
            if fields.is_empty() { return Err(StoreError::InvalidData); }
            let tx = state.connection.as_mut().ok_or(StoreError::Locked)?.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_error)?;
            let previous: Option<String> = tx.query_row("SELECT version FROM items WHERE id = ?1", [item.expose()], |row| row.get(0)).optional().map_err(db_error)?;
            match (previous, expected) {
                (None, None) => {
                    let count: i64 = tx.query_row("SELECT count(*) FROM items", [], |row| row.get(0)).map_err(db_error)?;
                    if count >= 1000 { return Err(StoreError::Unavailable); }
                },
                (Some(previous), Some(expected)) if expected.generation == state.generation && expected.version.as_str() == previous => {},
                _ => return Err(StoreError::Changed),
            }
            let version = Version::fresh()?;
            tx.execute("INSERT INTO items(id, version) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET version = excluded.version",
                params![item.expose(), version.as_str()]).map_err(db_error)?;
            tx.execute("DELETE FROM fields WHERE item_id = ?1", [item.expose()]).map_err(db_error)?;
            for (kind, value) in &fields {
                tx.execute("INSERT INTO fields(item_id, kind, value) VALUES (?1, ?2, ?3)",
                    params![item.expose(), kind.as_str(), value.expose()]).map_err(db_error)?;
            }
            tx.commit().map_err(db_error)?;
            Ok(ItemMetadata { lease: Lease { version, generation: state.generation.clone() }, fields: fields.keys().copied().collect(), valid_until: None })
        }))
    }
    fn delete<'a>(&'a self, item: &'a ItemRef, expected: &'a Lease) -> BoxFuture<'a, Result<()>> {
        let (item, expected) = (item.clone(), expected.clone());
        Box::pin(self.run(move |state| {
            let tx = state
                .connection
                .as_mut()
                .ok_or(StoreError::Locked)?
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_error)?;
            check_lease(&read_metadata(&tx, &item, &state.generation)?, &expected)?;
            tx.execute("DELETE FROM items WHERE id = ?1", [item.expose()])
                .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            Ok(())
        }))
    }
}

fn connect(directory: &PrivateDir, key: &SecretBytes, mode: OpenMode) -> Result<Connection> {
    let key = raw_key(key)?;
    let file = match mode {
        OpenMode::Create => directory.create_file(DATABASE),
        OpenMode::Existing => directory.open_file(DATABASE, true),
    }
    .map_err(|_| StoreError::Unavailable)?;
    if mode == OpenMode::Existing
        && file.metadata().map_err(|_| StoreError::Unavailable)?.len() == 0
    {
        return Err(StoreError::InvalidData);
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        match directory.open_file(&format!("{DATABASE}{suffix}"), true) {
            Ok(_) | Err(aap_config::Error::NotFound) => {}
            Err(_) => return Err(StoreError::Unavailable),
        }
    }
    // The path contains the deliberately trusted /proc/self/fd directory link.
    // PrivateDir has verified the final inode and excludes untrusted writers;
    // SQLite's all-components NOFOLLOW flag would reject this anchored path.
    let mut connection = Connection::open_with_flags(
        directory
            .backend_path(DATABASE)
            .map_err(|_| StoreError::Unavailable)?,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db_error)?;
    connection
        .pragma_update(None, "key", key)
        .map_err(db_error)?;
    let cipher: String = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(db_error)?;
    if cipher.is_empty() {
        return Err(StoreError::Unavailable);
    }
    let _: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .map_err(db_error)?;
    // Refuse foreign/newer schemas before any persistent journal-mode change.
    if mode == OpenMode::Existing {
        verify_schema(&connection)?;
    }
    connection
        .busy_timeout(Duration::from_secs(2))
        .map_err(db_error)?;
    connection
        .execute_batch(
            "PRAGMA trusted_schema = OFF; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY;
        PRAGMA secure_delete = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
        )
        .map_err(db_error)?;
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(db_error)?;
    let temporary: i64 = connection
        .query_row("PRAGMA temp_store", [], |row| row.get(0))
        .map_err(db_error)?;
    if journal != "wal" || temporary != 2 {
        return Err(StoreError::Unavailable);
    }
    if mode == OpenMode::Create {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        tx.execute_batch(
            "CREATE TABLE items (id TEXT PRIMARY KEY NOT NULL, version TEXT NOT NULL) STRICT;
            CREATE TABLE fields (item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                kind TEXT NOT NULL, value BLOB NOT NULL CHECK(length(value) BETWEEN 1 AND 65536),
                PRIMARY KEY(item_id, kind)) STRICT;
            PRAGMA application_id = 1094799409; PRAGMA user_version = 1;",
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)?;
    }
    verify_schema(&connection)?;
    directory.sync().map_err(|_| StoreError::Unavailable)?;
    Ok(connection)
}

fn backing_identity(directory: &PrivateDir) -> Result<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let file = directory
            .open_file(DATABASE, true)
            .map_err(|_| StoreError::Unavailable)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            match directory.open_file(&format!("{DATABASE}{suffix}"), true) {
                Ok(_) | Err(aap_config::Error::NotFound) => {}
                Err(_) => return Err(StoreError::Unavailable),
            }
        }
        let metadata = file.metadata().map_err(|_| StoreError::Unavailable)?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(StoreError::Unsupported)
    }
}

fn verify_schema(connection: &Connection) -> Result<()> {
    let application: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(db_error)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_error)?;
    if application != APPLICATION_ID || version != 1 {
        return Err(StoreError::InvalidData);
    }
    Ok(())
}

fn backup_connection(
    connection: &Connection,
    destination: &PrivateDir,
    encoded_key: &str,
) -> Result<()> {
    destination
        .create_file(DATABASE)
        .map_err(|_| StoreError::Unavailable)?;
    let path = destination
        .backend_path(DATABASE)
        .map_err(|_| StoreError::Unavailable)?;
    connection
        .execute(
            "ATTACH DATABASE ?1 AS aap_backup KEY ?2",
            params![path.to_str().ok_or(StoreError::InvalidData)?, encoded_key],
        )
        .map_err(db_error)?;
    let result = (|| {
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(db_error)?;
        connection
            .query_row("SELECT sqlcipher_export('aap_backup')", [], |_| Ok(()))
            .map_err(db_error)?;
        connection.execute_batch("PRAGMA aap_backup.application_id=1094799409; PRAGMA aap_backup.user_version=1; COMMIT").map_err(db_error)
    })();
    if result.is_err() {
        let _ = connection.execute_batch("ROLLBACK");
    }
    let detach = connection
        .execute_batch("DETACH DATABASE aap_backup")
        .map_err(db_error);
    result?;
    detach?;
    destination
        .open_file(DATABASE, true)
        .map_err(|_| StoreError::Unavailable)?
        .sync_all()
        .map_err(|_| StoreError::Unavailable)?;
    destination.sync().map_err(|_| StoreError::Unavailable)
}

fn raw_key(key: &SecretBytes) -> Result<String> {
    if key.expose().len() != 32 {
        return Err(StoreError::InvalidData);
    }
    use std::fmt::Write;
    let mut encoded = String::with_capacity(67);
    encoded.push_str("x'");
    for byte in key.expose() {
        write!(&mut encoded, "{byte:02x}").map_err(|_| StoreError::Unavailable)?;
    }
    encoded.push('\'');
    Ok(encoded)
}

fn read_metadata(
    connection: &Connection,
    item: &ItemRef,
    generation: &Version,
) -> Result<ItemMetadata> {
    let version: String = connection
        .query_row(
            "SELECT version FROM items WHERE id = ?1",
            [item.expose()],
            |row| row.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or(StoreError::NotFound)?;
    let mut statement = connection
        .prepare("SELECT kind FROM fields WHERE item_id = ?1")
        .map_err(db_error)?;
    let rows = statement
        .query_map([item.expose()], |row| row.get::<_, String>(0))
        .map_err(db_error)?;
    let mut fields = Vec::new();
    for row in rows {
        if fields.len() >= 6 {
            return Err(StoreError::InvalidData);
        }
        fields.push(Field::parse(&row.map_err(db_error)?)?);
    }
    fields.sort();
    if fields.is_empty() {
        return Err(StoreError::InvalidData);
    }
    Ok(ItemMetadata {
        lease: Lease {
            version: Version::from_persisted(version)?,
            generation: generation.clone(),
        },
        fields,
        valid_until: None,
    })
}

fn check_lease(metadata: &ItemMetadata, expected: &Lease) -> Result<()> {
    if &metadata.lease == expected {
        Ok(())
    } else {
        Err(StoreError::Changed)
    }
}

fn db_error(_error: rusqlite::Error) -> StoreError {
    StoreError::Unavailable
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use aap_secrets::{Availability, Field};
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::PathBuf,
    };

    const PASSWORD: &[u8] = b"SYNTHETIC-aap-password-never-real-482719";
    struct Fixture {
        path: PathBuf,
        directory: Arc<PrivateDir>,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::var_os("AAP_TEST_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(format!(
                    "aap-sqlite-tests-{}",
                    aap_types::ids::random_id(16).unwrap()
                ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let directory = Arc::new(PrivateDir::open(&path, false).unwrap());
            Self { path, directory }
        }
        async fn open(&self, mode: OpenMode, byte: u8) -> Result<SqliteStore> {
            SqliteStore::open(
                self.directory.clone(),
                key(byte),
                mode,
                tokio::runtime::Handle::current(),
            )
            .await
        }
        fn check_encrypted_files(&self) {
            for entry in fs::read_dir(&self.path).unwrap() {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                assert!(
                    !bytes
                        .windows(PASSWORD.len())
                        .any(|window| window == PASSWORD),
                    "plaintext credential in backend file"
                );
                assert!(
                    !bytes.starts_with(b"SQLite format 3\0"),
                    "plaintext SQLite header"
                );
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                    0o600
                );
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
    fn key(byte: u8) -> SecretBytes {
        SecretBytes::new(vec![byte; 32]).unwrap()
    }
    fn fields(password: &[u8]) -> SecretFields {
        BTreeMap::from([
            (
                Field::Username,
                SecretBytes::new(b"synthetic-account".to_vec()).unwrap(),
            ),
            (
                Field::Password,
                SecretBytes::new(password.to_vec()).unwrap(),
            ),
        ])
    }

    #[tokio::test]
    async fn cancelled_callers_keep_native_work_bounded_until_completion() {
        use std::{future::poll_fn, task::Poll};
        use tokio::{sync::oneshot, time::timeout};

        // The result owns actual synthetic SQLCipher data. Its drop signal
        // establishes disposal of an abandoned result, not memory zeroization.
        struct LateValue {
            _secret: SecretBytes,
            dropped: Option<oneshot::Sender<()>>,
        }
        impl Drop for LateValue {
            fn drop(&mut self) {
                if let Some(dropped) = self.dropped.take() {
                    let _ = dropped.send(());
                }
            }
        }

        let fixture = Fixture::new();
        let store = fixture.open(OpenMode::Create, 17).await.unwrap();
        let item = ItemRef::new("synthetic-item".into()).unwrap();
        let metadata = store.put(&item, fields(PASSWORD), None).await.unwrap();
        let snapshot = store.resolve(&item, &metadata.lease).await.unwrap();
        assert_eq!(snapshot.field(Field::Password).unwrap().expose(), PASSWORD);
        drop(snapshot);
        assert_eq!(store.budget.available_permits(), 8);

        let (entered, reached) = oneshot::channel();
        let (release, wait_release) = std::sync::mpsc::channel();
        let (dropped, result_disposed) = oneshot::channel();
        let mut native = Box::pin(store.run(move |state| {
            let connection = state.connection.as_ref().ok_or(StoreError::Locked)?;
            let value: Vec<u8> = connection.query_row(
                "SELECT value FROM fields WHERE item_id = 'synthetic-item' AND kind = 'password'",
                [], |row| row.get(0),
            ).map_err(db_error)?;
            let result = LateValue {
                _secret: SecretBytes::new(value)?,
                dropped: Some(dropped),
            };
            entered.send(()).map_err(|_| StoreError::Unavailable)?;
            wait_release
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| StoreError::Unavailable)?;
            Ok(result)
        }));
        poll_fn(|cx| {
            assert!(native.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        timeout(Duration::from_secs(2), reached)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(store.budget.available_permits(), 7);
        drop(native);
        assert_eq!(
            store.budget.available_permits(),
            7,
            "dropping the caller released a still-running native reservation"
        );

        // The first worker holds State while paused. Other admitted workers
        // cannot finish until release; dropping their callers must not admit
        // an unbounded replacement queue into the native runtime.
        let mut queued = vec![];
        for _ in 0..7 {
            let mut call = store.status();
            poll_fn(|cx| {
                assert!(call.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            queued.push(call);
        }
        assert_eq!(store.budget.available_permits(), 0);
        drop(queued);
        assert_eq!(
            store.budget.available_permits(),
            0,
            "abandoned queued native calls lost their reservations"
        );
        assert!(matches!(
            store.resolve(&item, &metadata.lease).await,
            Err(StoreError::Unavailable)
        ));
        assert!(
            matches!(store.lock().await, Err(StoreError::Unavailable)),
            "a saturated backend reported successful locking"
        );

        release.send(()).unwrap();
        timeout(Duration::from_secs(2), result_disposed)
            .await
            .unwrap()
            .unwrap();
        let all_slots = timeout(
            Duration::from_secs(2),
            store.budget.clone().acquire_many_owned(8),
        )
        .await
        .unwrap()
        .unwrap();
        drop(all_slots);
        assert_eq!(store.budget.available_permits(), 8);
        assert_eq!(
            store.status().await.unwrap().availability,
            Availability::Ready
        );
        assert_eq!(
            store
                .resolve(&item, &metadata.lease)
                .await
                .unwrap()
                .field(Field::Password)
                .unwrap()
                .expose(),
            PASSWORD
        );
        fixture.check_encrypted_files();
    }

    #[tokio::test]
    async fn credentials_round_trip_with_encrypted_wal_and_restart() {
        let fixture = Fixture::new();
        let store = fixture
            .open(OpenMode::Create, 17)
            .await
            .expect("encrypted store creation failed");
        let item = ItemRef::new("synthetic-item".into()).unwrap();
        let metadata = store.put(&item, fields(PASSWORD), None).await.unwrap();
        let snapshot = store.resolve(&item, &metadata.lease).await.unwrap();
        assert_eq!(snapshot.field(Field::Password).unwrap().expose(), PASSWORD);
        assert_eq!(metadata.fields, vec![Field::Username, Field::Password]);
        assert!(fixture.path.join("vault.sqlite3-wal").exists());
        fixture.check_encrypted_files();
        drop(store);
        assert!(fixture.open(OpenMode::Existing, 18).await.is_err());
        let reopened = fixture.open(OpenMode::Existing, 17).await.unwrap();
        assert!(matches!(
            reopened.resolve(&item, &metadata.lease).await,
            Err(StoreError::Changed)
        ));
        let fresh = reopened.metadata(&item).await.unwrap();
        assert_eq!(fresh.lease.version, metadata.lease.version);
        assert_eq!(
            reopened
                .resolve(&item, &fresh.lease)
                .await
                .unwrap()
                .field(Field::Password)
                .unwrap()
                .expose(),
            PASSWORD
        );
        fixture.check_encrypted_files();
    }

    #[tokio::test]
    async fn rotation_lock_and_deletion_invalidate_leases() {
        let fixture = Fixture::new();
        let store = fixture.open(OpenMode::Create, 17).await.unwrap();
        let item = ItemRef::new("synthetic-item".into()).unwrap();
        let first = store.put(&item, fields(PASSWORD), None).await.unwrap();
        assert!(matches!(
            store.put(&item, fields(PASSWORD), None).await,
            Err(StoreError::Changed)
        ));
        let next = store
            .put(
                &item,
                fields(b"rotated-synthetic-password"),
                Some(&first.lease),
            )
            .await
            .unwrap();
        assert_ne!(first.lease.version, next.lease.version);
        assert!(matches!(
            store.resolve(&item, &first.lease).await,
            Err(StoreError::Changed)
        ));
        assert!(matches!(
            store.delete(&item, &first.lease).await,
            Err(StoreError::Changed)
        ));
        store.lock().await.unwrap();
        assert_eq!(
            store.status().await.unwrap().availability,
            Availability::Locked
        );
        assert!(matches!(
            store.metadata(&item).await,
            Err(StoreError::Locked)
        ));
        assert!(store.unlock(key(18)).await.is_err());
        store.unlock(key(17)).await.unwrap();
        assert!(matches!(
            store.revalidate(&item, &next.lease).await,
            Err(StoreError::Changed)
        ));
        let current = store.metadata(&item).await.unwrap();
        store.delete(&item, &current.lease).await.unwrap();
        assert!(matches!(
            store.metadata(&item).await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn encrypted_backup_uses_its_own_key_and_preserves_records() {
        let source = Fixture::new();
        let destination = Fixture::new();
        let store = source.open(OpenMode::Create, 17).await.unwrap();
        let item = ItemRef::new("synthetic-item".into()).unwrap();
        let original = store.put(&item, fields(PASSWORD), None).await.unwrap();
        store
            .backup(destination.directory.clone(), key(23))
            .await
            .expect("encrypted backup failed");
        destination.check_encrypted_files();
        assert!(destination.open(OpenMode::Existing, 17).await.is_err());
        let backup = destination.open(OpenMode::Existing, 23).await.unwrap();
        let metadata = backup.metadata(&item).await.unwrap();
        assert_eq!(metadata.lease.version, original.lease.version);
        assert_eq!(
            backup
                .resolve(&item, &metadata.lease)
                .await
                .unwrap()
                .field(Field::Password)
                .unwrap()
                .expose(),
            PASSWORD
        );
        store.revalidate(&item, &original.lease).await.unwrap();
        assert!(
            store
                .backup(destination.directory.clone(), key(24))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn key_rotation_keeps_encrypted_recovery_and_rejects_old_key() {
        let source = Fixture::new();
        let recovery = Fixture::new();
        let store = source.open(OpenMode::Create, 17).await.unwrap();
        let item = ItemRef::new("synthetic-item".into()).unwrap();
        let original = store.put(&item, fields(PASSWORD), None).await.unwrap();
        store
            .rotate_key(key(37), recovery.directory.clone(), key(29))
            .await
            .expect("key rotation failed");
        assert!(matches!(
            store.revalidate(&item, &original.lease).await,
            Err(StoreError::Changed)
        ));
        drop(store);
        assert!(source.open(OpenMode::Existing, 17).await.is_err());
        let rotated = source.open(OpenMode::Existing, 37).await.unwrap();
        let restored = recovery.open(OpenMode::Existing, 29).await.unwrap();
        for store in [&rotated, &restored] {
            let metadata = store.metadata(&item).await.unwrap();
            assert_eq!(
                store
                    .resolve(&item, &metadata.lease)
                    .await
                    .unwrap()
                    .field(Field::Password)
                    .unwrap()
                    .expose(),
                PASSWORD
            );
        }
        source.check_encrypted_files();
        recovery.check_encrypted_files();
    }

    #[tokio::test]
    async fn unsupported_schema_is_rejected_without_persistent_changes() {
        let fixture = Fixture::new();
        let store = fixture.open(OpenMode::Create, 17).await.unwrap();
        store.run(|state| {
            state.connection.as_ref().unwrap().execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE; PRAGMA user_version=99;").map_err(db_error)
        }).await.unwrap();
        drop(store);
        let before = fs::read(fixture.path.join(DATABASE)).unwrap();
        assert!(fixture.open(OpenMode::Existing, 17).await.is_err());
        assert!(
            fs::read(fixture.path.join(DATABASE)).unwrap() == before,
            "unsupported schema was changed before rejection"
        );
    }

    #[tokio::test]
    async fn existing_mode_never_creates_or_replaces_a_vault() {
        let fixture = Fixture::new();
        assert!(fixture.open(OpenMode::Existing, 17).await.is_err());
        assert_eq!(fs::read_dir(&fixture.path).unwrap().count(), 0);
        let store = fixture
            .open(OpenMode::Create, 17)
            .await
            .expect("initial encrypted store creation failed");
        assert!(fixture.open(OpenMode::Create, 18).await.is_err());
        assert_eq!(
            store.status().await.unwrap().availability,
            Availability::Ready
        );
    }

    #[tokio::test]
    async fn backing_file_permission_loss_stops_secret_resolution() {
        let fixture = Fixture::new();
        let store = fixture.open(OpenMode::Create, 17).await.unwrap();
        let item = ItemRef::new("synthetic-item".into()).unwrap();
        let metadata = store.put(&item, fields(PASSWORD), None).await.unwrap();
        fs::set_permissions(
            fixture.path.join(DATABASE),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            matches!(
                store.resolve(&item, &metadata.lease).await,
                Err(StoreError::Unavailable)
            ),
            "credential resolved after file access became unsafe"
        );
        assert_eq!(
            store.status().await.unwrap().availability,
            Availability::Locked
        );
    }

    #[tokio::test]
    async fn backing_file_replacement_cannot_keep_old_access_alive() {
        let fixture = Fixture::new();
        let store = fixture.open(OpenMode::Create, 17).await.unwrap();
        let item = ItemRef::new("synthetic-item".into()).unwrap();
        let metadata = store.put(&item, fields(PASSWORD), None).await.unwrap();
        fs::rename(fixture.path.join(DATABASE), fixture.path.join("old.db")).unwrap();
        fixture.directory.create_file(DATABASE).unwrap();
        assert!(
            matches!(
                store.resolve(&item, &metadata.lease).await,
                Err(StoreError::Unavailable)
            ),
            "credential resolved from a detached old database"
        );
    }

    #[tokio::test]
    async fn plaintext_databases_and_invalid_key_lengths_never_fall_back() {
        let fixture = Fixture::new();
        let result = SqliteStore::open(
            fixture.directory.clone(),
            SecretBytes::new(vec![17; 31]).unwrap(),
            OpenMode::Create,
            tokio::runtime::Handle::current(),
        )
        .await;
        assert!(matches!(result, Err(StoreError::InvalidData)));
        assert_eq!(fs::read_dir(&fixture.path).unwrap().count(), 0);
        fixture.directory.create_file(DATABASE).unwrap();
        let plaintext =
            Connection::open(fixture.directory.backend_path(DATABASE).unwrap()).unwrap();
        plaintext
            .execute_batch(
                "CREATE TABLE unencrypted(value INTEGER); INSERT INTO unencrypted VALUES (1)",
            )
            .unwrap();
        drop(plaintext);
        let before = fs::read(fixture.path.join(DATABASE)).unwrap();
        assert!(before.starts_with(b"SQLite format 3\0"));
        assert!(fixture.open(OpenMode::Existing, 17).await.is_err());
        assert!(
            fs::read(fixture.path.join(DATABASE)).unwrap() == before,
            "plaintext input was replaced or migrated silently"
        );
    }

    #[tokio::test]
    async fn a_failed_field_update_rolls_back_the_entire_credential() {
        let fixture = Fixture::new();
        let store = fixture.open(OpenMode::Create, 17).await.unwrap();
        let item = ItemRef::new("synthetic-item".into()).unwrap();
        let original = store.put(&item, fields(PASSWORD), None).await.unwrap();
        store.run(|state| {
            state.connection.as_ref().unwrap().execute_batch("CREATE TRIGGER fail_password BEFORE INSERT ON fields
                WHEN NEW.kind = 'password' BEGIN SELECT RAISE(ABORT, 'synthetic write failure'); END;").map_err(db_error)
        }).await.unwrap();
        assert!(
            store
                .put(
                    &item,
                    fields(b"should-never-be-committed"),
                    Some(&original.lease)
                )
                .await
                .is_err()
        );
        assert!(
            store.revalidate(&item, &original.lease).await.is_ok(),
            "failed update changed the credential version"
        );
        let snapshot = store.resolve(&item, &original.lease).await.unwrap();
        assert_eq!(snapshot.field(Field::Password).unwrap().expose(), PASSWORD);
        assert_eq!(
            snapshot.field(Field::Username).unwrap().expose(),
            b"synthetic-account"
        );
    }
}
