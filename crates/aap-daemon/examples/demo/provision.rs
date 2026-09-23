use super::{Result, origin};
use aap_config::PrivateDir;
use aap_daemon::{Acceptance, DaemonConfig, ObservationConfig, SqliteConfiguration};
use aap_policy::{
    AddressPolicy, Authentication, Catalog, CredentialRef, Item, ItemApproval, ResourceProfile,
    Route,
};
use aap_secrets::{Field, ItemRef, SecretBytes, SecretStore, SecretStoreAdmin};
use aap_store_sqlite::{OpenMode, SqliteStore};
use aap_types::{CredentialFields, profile::*};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::json;
use std::{collections::HashMap, fs::File, os::unix::fs::DirBuilderExt, path::Path, sync::Arc};

const MARKER: &[u8] = b"aap-synthetic-demo-v1\n";

pub struct State {
    pub directory: PrivateDir,
    pub key: SecretBytes,
    _lock: File,
}

pub async fn open(root: &Path) -> Result<State> {
    // Keep resulting Unix-socket paths within Linux's pathname bound.
    if !root.is_absolute() || root.as_os_str().len() > 70 {
        return Err("use an absolute demo directory path of at most 70 bytes".into());
    }
    let created = match std::fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    let directory = PrivateDir::open(root, false)?;
    if !created && directory.read("demo-marker", 64)? != MARKER {
        return Err("not a recognized synthetic demo directory; choose a new directory".into());
    }
    let lock = if created {
        directory.create_file("demo.lock")?
    } else {
        directory.open_file("demo.lock", true)?
    };
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| "another demo owns this directory")?;
    for name in ["c", "s", "r"] {
        PrivateDir::open(&root.join(name), created)?;
    }
    let key = if created {
        let random = aap_types::ids::random_id(32).map_err(|_| "randomness unavailable")?;
        let key = URL_SAFE_NO_PAD.decode(random)?;
        // Demo-only convenience: this file MUST NOT become a real vault's unlock policy.
        directory.write_atomic("demo-unlock.key", &key, 32)?;
        key
    } else {
        directory.read("demo-unlock.key", 32)?
    };
    if key.len() != 32 {
        return Err("invalid demo unlock key; refusing to replace the store".into());
    }
    let store = SqliteStore::open(
        Arc::new(PrivateDir::open(&root.join("s"), false)?),
        SecretBytes::new(key.clone())?,
        if created {
            OpenMode::Create
        } else {
            OpenMode::Existing
        },
        tokio::runtime::Handle::current(),
    )
    .await?;
    for (name, fields) in [
        ("demo-api", vec![(Field::ApiKey, origin::API_KEY)]),
        (
            "demo-login",
            vec![
                (Field::Username, origin::USER),
                (Field::Password, origin::PASSWORD),
            ],
        ),
    ] {
        let item = ItemRef::new(name.into())?;
        if created {
            store
                .put(
                    &item,
                    fields
                        .iter()
                        .map(|(field, value)| {
                            Ok((*field, SecretBytes::new(value.as_bytes().to_vec())?))
                        })
                        .collect::<aap_secrets::Result<_>>()?,
                    None,
                )
                .await?;
        } else {
            let metadata = store.metadata(&item).await?;
            let snapshot = store.resolve(&item, &metadata.lease).await?;
            if metadata.fields.len() != fields.len()
                || fields.iter().any(|(field, value)| {
                    snapshot
                        .field(*field)
                        .map(|secret| secret.expose() != value.as_bytes())
                        .unwrap_or(true)
                })
            {
                return Err(
                    "demo contains non-demo credentials; refusing to use or replace them".into(),
                );
            }
        }
    }
    store.lock().await?;
    if created {
        directory.write_atomic("demo-marker", MARKER, 64)?;
    }
    Ok(State {
        directory,
        key: SecretBytes::new(key)?,
        _lock: lock,
    })
}

pub fn configure(root: &Path, origin: &origin::Origin) -> Result<()> {
    let route = |method: &str, path: &str| Route {
        method: method.into(),
        path: path.into(),
        query: None,
        max_request_bytes: 65536,
        max_response_bytes: 65536,
        allowed_headers: vec!["content-type".into()],
        streaming: false,
        require_approval: false,
    };
    let profiles = vec![
        ResourceProfile {
            id: "provider".into(),
            origin: origin.url(),
            addresses: AddressPolicy::Pinned(vec![origin.address.ip()]),
            routes: vec![route("POST", "/v1/chat/completions")],
            auth: Authentication::ApiKey {
                item_id: "api".into(),
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                provider: ProviderKind::OpenAiChat,
            },
        },
        ResourceProfile {
            id: "website".into(),
            origin: origin.url(),
            addresses: AddressPolicy::Pinned(vec![origin.address.ip()]),
            routes: vec![
                route("GET", "/login"),
                route("POST", "/session"),
                route("GET", "/protected"),
            ],
            auth: Authentication::Form {
                login: LoginProfile {
                    page: format!("{}/login", origin.url()),
                    target: format!("{}/session", origin.url()),
                    encoding: LoginEncoding::Form,
                    fields: CredentialFields {
                        username: "user".into(),
                        password: "password".into(),
                    },
                    username_visible: false,
                    post_login_redirect: None,
                    success: LoginSuccess {
                        status: 200,
                        cookie_names: vec!["session".into()],
                        json_pointer: "/authenticated".into(),
                        expected: json!(true),
                    },
                    csrf: Some(CsrfProfile {
                        response_pointer: "/csrf".into(),
                        submit_field: "csrf".into(),
                    }),
                },
            },
        },
    ];
    let catalog = Catalog {
        schema_version: 1,
        configuration_revision: 1,
        items: [
            ("api", "provider", "demo-api"),
            ("account", "website", "demo-login"),
        ]
        .into_iter()
        .map(|(item, profile, key)| Item {
            item_id: item.into(),
            label: format!("Synthetic demo {item}"),
            account_alias: "demo".into(),
            profile: profile.into(),
            credential: CredentialRef {
                store: "default".into(),
                key: key.into(),
            },
            approval: ItemApproval::Inherit,
        })
        .collect(),
    };
    let config = DaemonConfig {
        schema_version: 1,
        configuration_revision: 1,
        store: SqliteConfiguration {
            alias: "default".into(),
            directory: root.join("s"),
        },
        runtime_directory: root.join("r"),
        upstream_roots_der_base64: vec![STANDARD.encode(origin.certificate.as_ref())],
        interception: None,
        static_hosts: HashMap::from([("demo.test".into(), vec![origin.address.ip()])]),
        profiles,
        tcp_profiles: vec![],
        require_approval: false,
        observation: ObservationConfig {
            acceptance: Acceptance::LocalMemory,
            max_events: 4096,
            max_bytes: 4 * 1024 * 1024,
            required: true,
        },
    };
    let directory = PrivateDir::open(&root.join("c"), false)?;
    directory.write_atomic(
        "daemon.json",
        &serde_json::to_vec_pretty(&config)?,
        1024 * 1024,
    )?;
    directory.write_atomic(
        "catalog.json",
        &serde_json::to_vec_pretty(&catalog)?,
        1024 * 1024,
    )?;
    aap_daemon::load(&directory)?;
    Ok(())
}
