//! Trusted test orchestration only. Never compiled into the external client.
use aap_policy::{
    AddressPolicy, Authentication, Catalog, CredentialRef, Item, ItemApproval, ResourceProfile,
    Route,
};
use aap_secrets::{Field, ItemRef, SecretBytes, SecretStoreAdmin};
use aap_store_sqlite::{OpenMode, SqliteStore};
use aap_test_support::{Origin, Reply};
use aap_types::{
    CredentialFields,
    profile::{CsrfProfile, LoginEncoding, LoginProfile, LoginSuccess, ProviderKind},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const KEY: &str = "synthetic-reuse-api-key";
const USER: &str = "synthetic-reuse-user";
const PASSWORD: &str = "synthetic-reuse-password";

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
pub struct Fixture {
    pub origin: Origin,
    pub catalog: Catalog,
    pub profiles: Vec<ResourceProfile>,
    directory: Directory,
}
impl Fixture {
    pub fn root(&self) -> &std::path::Path {
        &self.directory.0
    }
    pub fn key() -> SecretBytes {
        SecretBytes::new(vec![41; 32]).unwrap()
    }
    pub async fn new(encoding: LoginEncoding) -> Self {
        let parent = std::env::var_os("AAP_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = Directory(parent.join(format!(
            "aap-reuse-{}",
            aap_types::ids::random_id(16).unwrap()
        )));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        for name in ["c", "s", "r"] {
            aap_config::PrivateDir::open(&directory.0.join(name), true).unwrap();
        }
        let cookies = Mutex::new(HashMap::<String, bool>::new());
        let origin = Origin::with_handler(move |request| {
            let mut cookies = cookies.lock().unwrap();
            let cookie = |name: &str| request.headers.get("cookie").and_then(|value|value.to_str().ok())
                .and_then(|value|value.split(';').find_map(|field|field.trim().strip_prefix(&format!("{name}="))))
                .expect("missing private fixture cookie").to_owned();
            let mut reply = match request.target.path() {
                "/v1/chat/completions" => {
                    assert_eq!(request.headers["authorization"],format!("Bearer {KEY}"));
                    assert!(!request.headers.contains_key("cookie"));
                    let input: Value = serde_json::from_slice(&request.body).unwrap();
                    let mut reply = Reply::body(format!("data: {KEY}\n\n"));
                    reply.headers.push(("content-type".into(),"text/event-stream".into()));
                    match input["messages"][0]["content"].as_str().unwrap() {
                        "hello" => {},
                        "lost" => { reply.disconnect=true; },
                        "cancel" => { reply.chunks=vec![Bytes::from_static(b"data: still working\n\n");8]; reply.delay=Duration::from_secs(1); },
                        _ => panic!("unexpected fixture provider action"),
                    }
                    return reply;
                },
                "/login" => {
                    assert!(!request.headers.contains_key("cookie"));
                    let id=(cookies.len()+1).to_string();
                    cookies.insert(id.clone(),false);
                    let mut reply=Reply::body(json!({"csrf":format!("synthetic-reuse-csrf-{id}"),"echo":format!("synthetic-reuse-pre-{id}")}).to_string());
                    reply.headers.push(("set-cookie".into(),format!("pre=synthetic-reuse-pre-{id}; Secure; HttpOnly; Path=/; SameSite=Strict")));
                    reply
                },
                "/session" => {
                    let pre=cookie("pre");
                    let id=pre.strip_prefix("synthetic-reuse-pre-").unwrap();
                    assert!(!cookies[id]);
                    let csrf=format!("synthetic-reuse-csrf-{id}");
                    if encoding == LoginEncoding::Form {
                        assert_eq!(request.body,format!("user={USER}&password={PASSWORD}&csrf={csrf}"));
                    } else {
                        assert_eq!(serde_json::from_slice::<Value>(&request.body).unwrap(),json!({"user":USER,"password":PASSWORD,"csrf":csrf}));
                    }
                    *cookies.get_mut(id).unwrap()=true;
                    let session=format!("synthetic-reuse-cookie-{id}");
                    let mut reply=Reply::body(json!({"authenticated":true,"echo":format!("{USER} {PASSWORD} {session}")}).to_string());
                    reply.headers.push(("set-cookie".into(),format!("session={session}; Secure; HttpOnly; Path=/; SameSite=Strict")));
                    reply
                },
                "/protected" => {
                    let value=cookie("session");
                    assert!(cookies[value.strip_prefix("synthetic-reuse-cookie-").unwrap()]);
                    Reply::body(json!({"data":"protected","echo":value}).to_string())
                },
                _=>panic!("unexpected fixture website route"),
            };
            reply.headers.push(("content-type".into(),"application/json".into()));
            reply
        }).await;
        let store = SqliteStore::open(
            Arc::new(aap_config::PrivateDir::open(&directory.0.join("s"), false).unwrap()),
            Self::key(),
            OpenMode::Create,
            tokio::runtime::Handle::current(),
        )
        .await
        .unwrap();
        for (reference, fields) in [
            ("private-api", vec![(Field::ApiKey, KEY)]),
            (
                "private-login",
                vec![(Field::Username, USER), (Field::Password, PASSWORD)],
            ),
        ] {
            store
                .put(
                    &ItemRef::new(reference.into()).unwrap(),
                    fields
                        .into_iter()
                        .map(|(field, value)| {
                            (field, SecretBytes::new(value.as_bytes().to_vec()).unwrap())
                        })
                        .collect(),
                    None,
                )
                .await
                .unwrap();
        }
        drop(store);
        let route = |method: &str, path: &str, streaming| Route {
            method: method.into(),
            path: path.into(),
            query: None,
            max_request_bytes: 256 * 1024,
            max_response_bytes: 256 * 1024,
            allowed_headers: vec!["content-type".into()],
            streaming,
            require_approval: false,
        };
        let profiles = vec![
            ResourceProfile {
                id: "provider".into(),
                origin: origin.origin(),
                addresses: AddressPolicy::Pinned(vec![origin.address.ip()]),
                routes: vec![route("POST", "/v1/chat/completions", true)],
                auth: Authentication::ApiKey {
                    item_id: "api".into(),
                    header: "authorization".into(),
                    prefix: "Bearer ".into(),
                    provider: ProviderKind::OpenAiChat,
                },
            },
            ResourceProfile {
                id: "website".into(),
                origin: origin.origin(),
                addresses: AddressPolicy::Pinned(vec![origin.address.ip()]),
                routes: vec![
                    route("GET", "/login", false),
                    route("POST", "/session", false),
                    route("GET", "/protected", false),
                ],
                auth: Authentication::Form {
                    login: LoginProfile {
                        page: format!("{}/login", origin.origin()),
                        target: format!("{}/session", origin.origin()),
                        encoding,
                        fields: CredentialFields {
                            username: if encoding == LoginEncoding::Form {
                                "user"
                            } else {
                                "/user"
                            }
                            .into(),
                            password: if encoding == LoginEncoding::Form {
                                "password"
                            } else {
                                "/password"
                            }
                            .into(),
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
                            submit_field: if encoding == LoginEncoding::Form {
                                "csrf"
                            } else {
                                "/csrf"
                            }
                            .into(),
                        }),
                    },
                },
            },
        ];
        let catalog = Catalog {
            schema_version: 1,
            configuration_revision: 1,
            items: [
                ("api", "provider", "private-api"),
                ("account", "website", "private-login"),
            ]
            .into_iter()
            .map(|(item, profile, key)| Item {
                item_id: item.into(),
                label: "Synthetic fixture".into(),
                account_alias: "test".into(),
                profile: profile.into(),
                credential: CredentialRef {
                    store: "default".into(),
                    key: key.into(),
                },
                approval: ItemApproval::Inherit,
            })
            .collect(),
        };
        Self {
            origin,
            catalog,
            profiles,
            directory,
        }
    }
    pub fn verify(&self, report: &Value, records: &[aap_observe::Record]) {
        assert_eq!(report["authenticated_sessions"], 2);
        assert_eq!(report["protected_reads"], 3);
        assert_eq!(report["completed"].as_array().unwrap().len(), 8);
        assert_eq!(report["uncertain"].as_array().unwrap().len(), 2);
        let responses = report["responses"]
            .as_array()
            .expect("missing public response evidence");
        assert_eq!(responses.len(), 12);
        assert_eq!(
            responses
                .iter()
                .filter(|response| response["complete"] == true)
                .count(),
            11
        );
        assert_eq!(report["metadata"].as_array().unwrap().len(), 5);
        assert_eq!(report["errors"].as_array().unwrap().len(), 7);
        private_free(&serde_json::to_vec(report).unwrap());
        for response in responses {
            private_free(
                &STANDARD
                    .decode(response["body_base64"].as_str().unwrap())
                    .unwrap(),
            );
            for header in response["headers"].as_array().unwrap() {
                assert_ne!(header[0], "set-cookie");
                private_free(&STANDARD.decode(header[1].as_str().unwrap()).unwrap());
            }
        }
        let requests = self.origin.requests.lock().unwrap();
        assert_eq!(requests.len(), 10, "extra or missing upstream action");
        assert_eq!(
            self.origin.accepted_connections(),
            10,
            "unaccounted upstream connection"
        );
        let jars: Vec<_> = requests
            .iter()
            .filter(|request| request.target.path() == "/protected")
            .map(|request| {
                request.headers["cookie"]
                    .to_str()
                    .unwrap()
                    .split(';')
                    .find_map(|field| field.trim().strip_prefix("session="))
                    .unwrap()
            })
            .collect();
        assert_eq!(jars.len(), 3);
        assert_ne!(jars[0], jars[1], "independent logins shared authentication");
        assert_eq!(
            jars[1], jars[2],
            "logout changed the other session's cookie"
        );
        let ids: std::collections::BTreeSet<_> = ["completed", "uncertain"]
            .into_iter()
            .flat_map(|field| report[field].as_array().unwrap().iter())
            .map(|id| id.as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 10, "report repeated an operation ID");
        for (field, complete) in [("completed", true), ("uncertain", false)] {
            for id in report[field].as_array().unwrap() {
                for view in [aap_observe::View::Agent, aap_observe::View::Upstream] {
                    let endings: Vec<_> = records
                        .iter()
                        .filter(|record| {
                            record.event.request_id.as_deref() == id.as_str()
                                && record.event.view == view
                                && matches!(record.event.data, aap_observe::Data::FlowClose { .. })
                        })
                        .collect();
                    assert_eq!(endings.len(), 1);
                    assert!(
                        matches!(endings[0].event.data,aap_observe::Data::FlowClose{complete:actual,..} if actual==complete)
                    );
                }
            }
        }
        for record in records {
            safe(&serde_json::to_vec(record).unwrap());
            if let aap_observe::Data::ContentChunk { body_base64, .. } = &record.event.data {
                safe(&STANDARD.decode(body_base64).unwrap());
            }
        }
    }
}
fn private_free(bytes: &[u8]) {
    let value = String::from_utf8_lossy(bytes);
    for private in [
        KEY,
        USER,
        PASSWORD,
        "synthetic-reuse-csrf-",
        "synthetic-reuse-pre-",
        "synthetic-reuse-cookie-",
        "private-api",
        "private-login",
    ] {
        assert!(
            !value.contains(private),
            "private field escaped the trusted fixture"
        );
    }
}
fn safe(bytes: &[u8]) {
    private_free(bytes);
    let value = String::from_utf8_lossy(bytes);
    for placeholder in ["aap_pw1_", "aap_un1_", "aap_cs1_"] {
        assert!(
            !value.contains(placeholder),
            "placeholder escaped into observation"
        );
    }
}
