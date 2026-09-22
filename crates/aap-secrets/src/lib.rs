//! Backend-neutral secret custody for trusted hosts, never an agent retrieval API.

use aap_types::BoxFuture;
use std::{collections::BTreeMap, time::Instant};

/// Intentional byte access, without implicit formatting, serialization or cloning.
/// This prevents accidental disclosure; it does not guarantee memory erasure.
///
/// ```compile_fail
/// use aap_secrets::SecretBytes;
/// let secret = SecretBytes::new(b"synthetic".to_vec()).unwrap();
/// println!("{secret:?}");
/// ```
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(StoreError::InvalidData);
        }
        Ok(Self(bytes))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// An adapter-private reference. It is not safe operator/agent log metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemRef(String);

impl ItemRef {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() || value.len() > 16_384 || value.chars().any(char::is_control) {
            return Err(StoreError::InvalidData);
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Random opaque revision, never a fingerprint derived from credential bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version(String);

impl Version {
    pub fn fresh() -> Result<Self> {
        aap_types::ids::random_id(32)
            .map(Self)
            .map_err(|_| StoreError::Unavailable)
    }
    pub fn from_persisted(value: String) -> Result<Self> {
        if !aap_types::ids::valid_id(&value, 32) {
            return Err(StoreError::InvalidData);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    Username,
    Password,
    ApiKey,
    AccessToken,
    RefreshToken,
    PrivateKey,
}

impl Field {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::ApiKey => "api_key",
            Self::AccessToken => "access_token",
            Self::RefreshToken => "refresh_token",
            Self::PrivateKey => "private_key",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "username" => Ok(Self::Username),
            "password" => Ok(Self::Password),
            "api_key" => Ok(Self::ApiKey),
            "access_token" => Ok(Self::AccessToken),
            "refresh_token" => Ok(Self::RefreshToken),
            "private_key" => Ok(Self::PrivateKey),
            _ => Err(StoreError::InvalidData),
        }
    }
}

pub type SecretFields = BTreeMap<Field, SecretBytes>;

/// Both the item and store-access generation must still match at resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub version: Version,
    pub generation: Version,
}

#[derive(Clone, Debug)]
pub struct ItemMetadata {
    pub lease: Lease,
    pub fields: Vec<Field>,
    pub valid_until: Option<Instant>,
}

pub struct Snapshot {
    metadata: ItemMetadata,
    fields: SecretFields,
}

impl Snapshot {
    pub fn new(metadata: ItemMetadata, fields: SecretFields) -> Result<Self> {
        let kinds: std::collections::BTreeSet<_> = metadata.fields.iter().copied().collect();
        if fields.is_empty()
            || kinds.len() != metadata.fields.len()
            || kinds.len() != fields.len()
            || !fields.keys().all(|kind| kinds.contains(kind))
            || metadata
                .valid_until
                .is_some_and(|deadline| deadline <= Instant::now())
        {
            return Err(StoreError::InvalidData);
        }
        Ok(Self { metadata, fields })
    }
    pub fn metadata(&self) -> &ItemMetadata {
        &self.metadata
    }
    pub fn field(&self, field: Field) -> Result<&SecretBytes> {
        self.fields.get(&field).ok_or(StoreError::InvalidData)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Ready,
    Locked,
    Unavailable,
    InteractionRequired,
}

#[derive(Clone, Debug)]
pub struct StoreStatus {
    pub availability: Availability,
    pub generation: Version,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Locked,
    Unavailable,
    NotFound,
    AccessDenied,
    Changed,
    InteractionRequired,
    InvalidData,
    Unsupported,
}

pub type Result<T> = std::result::Result<T, StoreError>;

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "credential store operation failed: {self:?}")
    }
}
impl std::error::Error for StoreError {}

impl From<StoreError> for aap_types::Error {
    fn from(error: StoreError) -> Self {
        use aap_types::ErrorCode;
        Self::new(match error {
            StoreError::Locked => ErrorCode::VaultLocked,
            StoreError::AccessDenied | StoreError::NotFound => ErrorCode::PolicyDenied,
            StoreError::InteractionRequired => ErrorCode::InteractionUnavailable,
            _ => ErrorCode::VaultUnavailable,
        })
    }
}

/// Trusted read/use interface. Implementations must bound blocking/native work.
/// No method enumerates an entire native vault or accepts an agent grant override.
pub trait SecretStore: Send + Sync {
    fn status(&self) -> BoxFuture<'_, Result<StoreStatus>>;
    fn metadata<'a>(&'a self, item: &'a ItemRef) -> BoxFuture<'a, Result<ItemMetadata>>;
    fn resolve<'a>(
        &'a self,
        item: &'a ItemRef,
        expected: &'a Lease,
    ) -> BoxFuture<'a, Result<Snapshot>>;
    fn revalidate<'a>(
        &'a self,
        item: &'a ItemRef,
        expected: &'a Lease,
    ) -> BoxFuture<'a, Result<()>>;
}

/// Optional trusted management capability, never handed to agent-facing code.
pub trait SecretStoreAdmin: Send + Sync {
    /// No expected revision means create-only. A supplied revision is compare-and-swap.
    fn put<'a>(
        &'a self,
        item: &'a ItemRef,
        fields: SecretFields,
        expected: Option<&'a Lease>,
    ) -> BoxFuture<'a, Result<ItemMetadata>>;
    fn delete<'a>(&'a self, item: &'a ItemRef, expected: &'a Lease) -> BoxFuture<'a, Result<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_have_bounded_explicit_access() {
        let bytes =
            SecretBytes::new(b"synthetic-password".to_vec()).expect("valid credential rejected");
        assert_eq!(bytes.expose(), b"synthetic-password");
        assert!(SecretBytes::new(vec![]).is_err());
        assert!(SecretBytes::new(vec![0; 65_537]).is_err());
    }

    #[test]
    fn references_and_versions_are_validated_without_secret_derivation() {
        assert!(
            ItemRef::new("native-reference".into()).is_ok(),
            "valid native reference rejected"
        );
        for invalid in ["".to_string(), "bad\nreference".into(), "x".repeat(16_385)] {
            assert!(ItemRef::new(invalid).is_err());
        }
        let version = Version::fresh().unwrap();
        assert_eq!(
            Version::from_persisted(version.as_str().to_string()).unwrap(),
            version
        );
        assert!(Version::from_persisted("credential-derived-value".into()).is_err());
        assert_ne!(Version::fresh().unwrap(), version);
    }

    #[test]
    fn snapshots_require_matching_field_metadata_and_live_validity() {
        let metadata = ItemMetadata {
            lease: Lease {
                version: Version::fresh().unwrap(),
                generation: Version::fresh().unwrap(),
            },
            fields: vec![Field::Password],
            valid_until: None,
        };
        let fields =
            || BTreeMap::from([(Field::Password, SecretBytes(b"synthetic-password".to_vec()))]);
        assert!(
            Snapshot::new(metadata.clone(), fields()).is_ok(),
            "coherent snapshot rejected"
        );
        let mut invalid = metadata.clone();
        invalid.fields.push(Field::Username);
        assert!(Snapshot::new(invalid, fields()).is_err());
        let mut invalid = metadata.clone();
        invalid.fields.push(Field::Password);
        assert!(Snapshot::new(invalid, fields()).is_err());
        let mut invalid = metadata;
        invalid.valid_until = Some(Instant::now());
        assert!(Snapshot::new(invalid, fields()).is_err());
    }
}
