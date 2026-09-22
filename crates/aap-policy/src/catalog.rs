//! Private operator catalog. This is never serialized to agent discovery verbatim.

use aap_types::{
    ErrorCode, Result,
    profile::{LoginProfile, ProviderKind},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub configuration_revision: u64,
    pub items: Vec<Item>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub item_id: String,
    pub label: String,
    pub account_alias: String,
    pub profile: String,
    pub credential: CredentialRef,
    #[serde(default)]
    pub approval: ItemApproval,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub store: String,
    pub key: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemApproval {
    #[default]
    Inherit,
    Authenticate,
    Always,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProfile {
    pub id: String,
    pub origin: String,
    pub addresses: AddressPolicy,
    pub routes: Vec<Route>,
    pub auth: Authentication,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "addresses",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AddressPolicy {
    Public,
    Pinned(Vec<IpAddr>),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub streaming: bool,
    #[serde(default)]
    pub require_approval: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authentication {
    None,
    ApiKey {
        item_id: String,
        header: String,
        prefix: String,
        provider: ProviderKind,
    },
    Form {
        login: LoginProfile,
    },
}

impl Catalog {
    pub fn validate(
        &self,
        profiles: &[ResourceProfile],
        stores: &[&str],
        revision: u64,
    ) -> Result<()> {
        let invalid = || aap_types::Error::new(ErrorCode::RequestInvalid);
        if self.schema_version != 1
            || revision == 0
            || self.configuration_revision != revision
            || self.items.len() > 1000
            || profiles.len() > 256
            || stores.len() > 64
        {
            return Err(invalid());
        }
        let mut store_ids = HashSet::new();
        for store in stores {
            if !valid_alias(store) || !store_ids.insert(*store) {
                return Err(invalid());
            }
        }
        let mut profile_ids = HashSet::new();
        for profile in profiles {
            profile.validate()?;
            if !profile_ids.insert(profile.id.as_str()) {
                return Err(invalid());
            }
        }
        let mut item_ids = HashSet::new();
        for item in &self.items {
            if !valid_alias(&item.item_id)
                || !item_ids.insert(item.item_id.as_str())
                || !valid_alias(&item.account_alias)
                || !profile_ids.contains(item.profile.as_str())
                || !store_ids.contains(item.credential.store.as_str())
                || item.label.is_empty()
                || item.label.len() > 256
                || item.label.chars().any(char::is_control)
                || item.credential.key.is_empty()
                || item.credential.key.len() > 16_384
                || item.credential.key.chars().any(char::is_control)
            {
                return Err(invalid());
            }
        }
        for profile in profiles {
            if let Authentication::ApiKey { item_id, .. } = &profile.auth
                && !self
                    .items
                    .iter()
                    .any(|item| &item.item_id == item_id && item.profile == profile.id)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

impl AddressPolicy {
    /// Admit a complete resolver result, never silently ignore forbidden candidates.
    pub fn permits_all(&self, addresses: &[IpAddr]) -> bool {
        !addresses.is_empty()
            && addresses.len() <= 64
            && addresses.iter().all(|address| match self {
                Self::Public => crate::is_public_address(*address),
                Self::Pinned(pins) => pins.contains(address),
            })
    }
}

impl Route {
    pub fn authorize_headers(&self, headers: &[(String, String)]) -> Result<()> {
        let denied = || aap_types::Error::new(ErrorCode::PolicyDenied);
        if headers.len() > 64 {
            return Err(denied());
        }
        let mut seen = HashSet::new();
        let mut bytes = 0usize;
        for (name, value) in headers {
            let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| denied())?;
            bytes = bytes
                .saturating_add(name.as_str().len())
                .saturating_add(value.len());
            if bytes > 65_536
                || !value.is_ascii()
                || http::HeaderValue::from_str(value).is_err()
                || routing_header(name.as_str())
                || name == http::header::AUTHORIZATION
                || !seen.insert(name.clone())
                || !self
                    .allowed_headers
                    .iter()
                    .any(|allowed| allowed == name.as_str())
            {
                return Err(denied());
            }
        }
        Ok(())
    }
}

pub(crate) fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 64
        && alias.as_bytes()[0].is_ascii_alphanumeric()
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The transport/engine, not caller-selected fields, owns routing and framing.
pub(crate) fn routing_header(name: &str) -> bool {
    name.starts_with("proxy-")
        || name.starts_with("x-forwarded-")
        || matches!(
            name,
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "te"
                | "trailer"
                | "upgrade"
                | "keep-alive"
                | "expect"
                | "cookie"
                | "set-cookie"
                | "forwarded"
                | "via"
                | "origin"
                | "referer"
        )
}

/// An item may add requirements but cannot disable host/session/action approval.
pub fn requires_approval(
    host: bool,
    session: bool,
    route: bool,
    item: ItemApproval,
    authentication: bool,
) -> bool {
    host || session
        || route
        || item == ItemApproval::Always
        || (item == ItemApproval::Authenticate && authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_requirements_cannot_be_relaxed_by_an_item() {
        assert!(
            requires_approval(true, false, false, ItemApproval::Inherit, false),
            "global approval bypassed"
        );
        assert!(requires_approval(
            false,
            true,
            false,
            ItemApproval::Inherit,
            false
        ));
        assert!(requires_approval(
            false,
            false,
            true,
            ItemApproval::Inherit,
            false
        ));
        assert!(requires_approval(
            false,
            false,
            false,
            ItemApproval::Always,
            false
        ));
        assert!(requires_approval(
            false,
            false,
            false,
            ItemApproval::Authenticate,
            true
        ));
        assert!(!requires_approval(
            false,
            false,
            false,
            ItemApproval::Authenticate,
            false
        ));
        assert!(!requires_approval(
            false,
            false,
            false,
            ItemApproval::Inherit,
            false
        ));
    }

    #[test]
    fn unknown_catalog_versions_and_orphaned_items_fail_closed() {
        let mut catalog = Catalog {
            schema_version: 2,
            configuration_revision: 1,
            items: vec![],
        };
        assert!(
            catalog.validate(&[], &["default"], 1).is_err(),
            "unsupported catalog version accepted"
        );
        catalog.schema_version = 1;
        assert!(catalog.validate(&[], &["default"], 1).is_ok());
        catalog.items.push(Item {
            item_id: "site".into(),
            label: "Account".into(),
            account_alias: "work".into(),
            profile: "missing".into(),
            credential: CredentialRef {
                store: "default".into(),
                key: "native-ref".into(),
            },
            approval: ItemApproval::Inherit,
        });
        assert!(catalog.validate(&[], &["default"], 1).is_err());
    }

    #[test]
    fn catalog_requires_matching_revisions_and_unique_valid_bindings() {
        let profile = crate::target::tests::profile();
        let mut catalog = Catalog {
            schema_version: 1,
            configuration_revision: 1,
            items: vec![],
        };
        assert!(
            catalog
                .validate(std::slice::from_ref(&profile), &["default"], 2)
                .is_err(),
            "mixed revisions accepted"
        );
        catalog.configuration_revision = 0;
        assert!(
            catalog
                .validate(std::slice::from_ref(&profile), &["default"], 0)
                .is_err()
        );
        catalog.configuration_revision = 1;
        let item = Item {
            item_id: "site".into(),
            label: "Account".into(),
            account_alias: "work".into(),
            profile: "site".into(),
            credential: CredentialRef {
                store: "default".into(),
                key: "native-ref".into(),
            },
            approval: ItemApproval::Inherit,
        };
        catalog.items.push(item.clone());
        assert!(
            catalog
                .validate(std::slice::from_ref(&profile), &["default"], 1)
                .is_ok()
        );
        assert!(
            catalog
                .validate(std::slice::from_ref(&profile), &["other"], 1)
                .is_err()
        );
        catalog.items.push(item);
        assert!(
            catalog
                .validate(std::slice::from_ref(&profile), &["default"], 1)
                .is_err()
        );
        catalog.items.pop();
        catalog.items[0].label.push('\n');
        assert!(catalog.validate(&[profile], &["default"], 1).is_err());
    }

    #[test]
    fn addresses_require_a_nonempty_fully_admitted_resolution() {
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(
            AddressPolicy::Public.permits_all(&[public]),
            "ordinary public resolution denied"
        );
        assert!(!AddressPolicy::Public.permits_all(&[]));
        assert!(!AddressPolicy::Public.permits_all(&[public, local]));
        let policy = AddressPolicy::Pinned(vec![local]);
        assert!(policy.permits_all(&[local]));
        assert!(!policy.permits_all(&[local, public]));
    }

    #[test]
    fn headers_cannot_smuggle_routing_credentials_or_framing() {
        let route = crate::target::tests::profile().routes.remove(0);
        assert!(
            route
                .authorize_headers(&[("content-type".into(), "application/json".into())])
                .is_ok()
        );
        for (name, value) in [
            ("authorization", "Bearer attack"),
            ("cookie", "auth=attack"),
            ("host", "other.test"),
            ("transfer-encoding", "chunked"),
            ("content-length", "4"),
            ("connection", "content-type"),
            ("proxy-auth-context", "attack"),
            ("content-type", "x\r\nHost: other.test"),
            ("x-unapproved", "x"),
        ] {
            assert!(
                route
                    .authorize_headers(&[(name.into(), value.into())])
                    .is_err(),
                "unsafe header accepted: {name}"
            );
        }
        assert!(
            route
                .authorize_headers(&[
                    ("content-type".into(), "x".into()),
                    ("Content-Type".into(), "y".into())
                ])
                .is_err()
        );
    }
}
