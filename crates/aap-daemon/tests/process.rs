#![cfg(target_os = "linux")]
use aap_daemon::*;
use aap_policy::{
    AddressPolicy, Authentication, Catalog, CredentialRef, Item, ItemApproval, ResourceProfile,
    Route,
};
use aap_secrets::{Field, ItemRef, SecretBytes, SecretStoreAdmin};
use aap_store_sqlite::{OpenMode, SqliteStore};
use aap_test_support::{Origin, Reply};
use aap_types::{AgentService, ErrorCode, ExecuteRequest, OperationState, profile::ProviderKind};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    collections::HashMap, os::unix::fs::DirBuilderExt, path::PathBuf, process::Stdio, sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[path = "process/interception.rs"]
mod interception;
#[path = "process/observation.rs"]
mod observation;
#[path = "process/remote_mcp.rs"]
mod remote_mcp;
#[path = "process/tcp.rs"]
mod tcp;

struct Fixture {
    root: PathBuf,
    origin: Origin,
    config: DaemonConfig,
    catalog: Catalog,
}
impl Fixture {
    async fn new() -> Self {
        let parent = std::env::var_os("AAP_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = parent.join(format!("aap-d-{}", aap_types::ids::random_id(16).unwrap()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        for child in ["c", "s", "r"] {
            aap_config::PrivateDir::open(&root.join(child), true).unwrap();
        }
        let mut reply = Reply::body("data: synthetic-daemon-key\n\n");
        reply
            .headers
            .push(("content-type".into(), "text/event-stream".into()));
        let origin = Origin::spawn(reply).await;
        let store = SqliteStore::open(
            Arc::new(aap_config::PrivateDir::open(&root.join("s"), false).unwrap()),
            SecretBytes::new(vec![17; 32]).unwrap(),
            OpenMode::Create,
            tokio::runtime::Handle::current(),
        )
        .await
        .unwrap();
        store
            .put(
                &ItemRef::new("private-key-ref".into()).unwrap(),
                [(
                    Field::ApiKey,
                    SecretBytes::new(b"synthetic-daemon-key".to_vec()).unwrap(),
                )]
                .into(),
                None,
            )
            .await
            .unwrap();
        drop(store);
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
            static_hosts: HashMap::from([("fixture.test".into(), vec![origin.address.ip()])]),
            require_approval: false,
            tcp_profiles: vec![],
            observation: ObservationConfig {
                acceptance: Acceptance::LocalMemory,
                max_events: 1024,
                max_bytes: 4 * 1024 * 1024,
                required: true,
            },
            profiles: vec![ResourceProfile {
                id: "provider".into(),
                origin: origin.origin(),
                addresses: AddressPolicy::Pinned(vec![origin.address.ip()]),
                routes: vec![Route {
                    method: "POST".into(),
                    path: "/v1/chat/completions".into(),
                    query: None,
                    max_request_bytes: 1024 * 1024,
                    max_response_bytes: 1024 * 1024,
                    allowed_headers: vec!["content-type".into()],
                    streaming: true,
                    require_approval: false,
                }],
                auth: Authentication::ApiKey {
                    item_id: "key".into(),
                    header: "authorization".into(),
                    prefix: "Bearer ".into(),
                    provider: ProviderKind::OpenAiChat,
                },
            }],
        };
        let catalog = Catalog {
            schema_version: 1,
            configuration_revision: 1,
            items: vec![Item {
                item_id: "key".into(),
                label: "Synthetic provider".into(),
                account_alias: "test".into(),
                profile: "provider".into(),
                credential: CredentialRef {
                    store: "default".into(),
                    key: "private-key-ref".into(),
                },
                approval: ItemApproval::Inherit,
            }],
        };
        let fixture = Self {
            root,
            origin,
            config,
            catalog,
        };
        fixture.write();
        fixture
    }
    fn write(&self) {
        let directory = aap_config::PrivateDir::open(&self.root.join("c"), false).unwrap();
        directory
            .write_atomic(
                "daemon.json",
                &serde_json::to_vec(&self.config).unwrap(),
                1024 * 1024,
            )
            .unwrap();
        directory
            .write_atomic(
                "catalog.json",
                &serde_json::to_vec(&self.catalog).unwrap(),
                1024 * 1024,
            )
            .unwrap();
    }
    async fn start(&self) -> (tokio::process::Child, Ready) {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-auth-proxy"))
            .arg("serve")
            .arg(self.root.join("c"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let _ = input.write_all(&[17; 32]).await;
        drop(input);
        let stdout = child.stdout.take().unwrap();
        let line = tokio::time::timeout(
            Duration::from_secs(5),
            BufReader::new(stdout).lines().next_line(),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("daemon exited before readiness");
        let ready: Ready = serde_json::from_str(&line).expect("invalid daemon readiness record");
        (child, ready)
    }
    fn request(&self) -> ExecuteRequest {
        ExecuteRequest { request_id: aap_types::ids::random_id(16).unwrap(), resource: "provider".into(), auth_context: None, method: "POST".into(), target: format!("{}/v1/chat/completions", self.origin.origin()), headers: vec![("content-type".into(), "application/json".into())], body_base64: STANDARD.encode(br#"{"model":"fixture","messages":[{"role":"user","content":"hello"}],"stream":true}"#) }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
async fn local(path: PathBuf, method: &str, body: Value) -> (http::StatusCode, Value) {
    let stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri(method)
                .header("host", "aap.local")
                .header("content-type", "application/json")
                .header("connection", "close")
                .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    driver.abort();
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn stop(child: &mut tokio::process::Child) {
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn standalone_process_brokers_a_private_session_and_read_only_observation() {
    let fixture = Fixture::new().await;
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(&ready.control_socket);
    let observer = fixture.root.join("r").join(&ready.observation_socket);
    let (status, attachment) = local(
        control.clone(),
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":60}),
    )
    .await;
    assert!(status.is_success());
    let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
    let client = aap_client::DaemonSessionClient::new(
        fixture.root.join("r").join(&attachment.ingress_socket),
    );
    let request = fixture.request();
    let response = client.execute(request.clone()).await.unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "data: [redacted]\n\n"
    );
    assert_eq!(
        client
            .request_status(request.request_id)
            .await
            .unwrap()
            .state,
        OperationState::Completed
    );
    assert_eq!(
        fixture.origin.requests.lock().unwrap()[0].headers["authorization"],
        "Bearer synthetic-daemon-key"
    );
    let (status, batch) = local(
        observer.clone(),
        "/aap/observe/v1/read",
        json!({"limit":128}),
    )
    .await;
    assert!(status.is_success());
    let batch: aap_observe::Batch = serde_json::from_value(batch).unwrap();
    assert!(!batch.records.is_empty());
    for record in &batch.records {
        if let aap_observe::Data::ContentChunk { body_base64, .. } = &record.event.data {
            assert!(
                !String::from_utf8_lossy(&STANDARD.decode(body_base64).unwrap())
                    .contains("synthetic-daemon-key")
            );
        }
    }
    assert!(
        local(
            observer,
            "/aap/operator/v1/session/create",
            json!({"resources":["provider"],"lifetime_seconds":60})
        )
        .await
        .0
        .is_client_error()
    );
    assert!(
        local(
            fixture.root.join("r").join(&attachment.ingress_socket),
            "/aap/operator/v1/session/create",
            json!({"resources":["provider"],"lifetime_seconds":60})
        )
        .await
        .0
        .is_client_error()
    );
    assert!(
        local(
            control,
            "/aap/operator/v1/session/revoke",
            json!({"session_id":attachment.session_id})
        )
        .await
        .0
        .is_success()
    );
    assert!(
        matches!(client.execute(fixture.request()).await, Err(error) if error.code == ErrorCode::SessionInvalid || error.code == ErrorCode::OutcomeUnknown)
    );
    stop(&mut child).await;
    assert!(!fixture.root.join("r").join(ready.control_socket).exists());
}

#[tokio::test]
async fn invalid_reload_preserves_authority_and_valid_reload_revokes_old_sessions() {
    let mut fixture = Fixture::new().await;
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(ready.control_socket);
    let (_, attachment) = local(
        control.clone(),
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":60}),
    )
    .await;
    let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
    let client = aap_client::DaemonSessionClient::new(
        fixture.root.join("r").join(attachment.ingress_socket),
    );
    fixture.config.configuration_revision = 2;
    fixture.write();
    assert!(
        local(control.clone(), "/aap/operator/v1/reload", json!({}))
            .await
            .0
            .is_client_error()
    );
    client
        .execute(fixture.request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    fixture.catalog.configuration_revision = 2;
    fixture.catalog.items.clear();
    fixture.config.profiles.clear();
    fixture.write();
    assert!(
        local(control.clone(), "/aap/operator/v1/reload", json!({}))
            .await
            .0
            .is_success()
    );
    assert!(client.execute(fixture.request()).await.is_err());
    assert!(
        local(
            control,
            "/aap/operator/v1/session/create",
            json!({"resources":["provider"],"lifetime_seconds":60})
        )
        .await
        .0
        .is_client_error()
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    stop(&mut child).await;
}

#[tokio::test]
async fn startup_checks_private_configuration_unlock_and_single_owner() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new().await;
    let validate = || {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-auth-proxy"));
        command
            .arg("validate")
            .arg(fixture.root.join("c"))
            .stdin(Stdio::null())
            .kill_on_drop(true);
        command
    };
    let output = validate().output().await.unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({"valid":true,"configuration_revision":1})
    );
    assert!(!fixture.root.join("r/control.json").exists());
    let path = fixture.root.join("c/catalog.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = validate().output().await.unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-key-ref"));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();

    for key in [vec![], vec![18; 32], vec![17; 33]] {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-auth-proxy"))
            .arg("serve")
            .arg(fixture.root.join("c"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(&key).await.unwrap();
        drop(input);
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!fixture.root.join("r/control.json").exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-daemon-key"));
    }
    let (mut first, ready) = fixture.start().await;
    let mut second = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-auth-proxy"))
        .arg("serve")
        .arg(fixture.root.join("c"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = second.stdin.take().unwrap();
    input.write_all(&[17; 32]).await.unwrap();
    drop(input);
    let output = tokio::time::timeout(Duration::from_secs(5), second.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("{}\n", aap_types::Error::new(ErrorCode::RequestConflict))
    );
    assert!(
        local(
            fixture.root.join("r").join(ready.control_socket),
            "/aap/operator/v1/status",
            json!({})
        )
        .await
        .0
        .is_success()
    );
    stop(&mut first).await;
}

#[tokio::test]
async fn process_death_invalidates_old_attachments_without_resetting_vault() {
    let fixture = Fixture::new().await;
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(&ready.control_socket);
    let (_, attachment) = local(
        control,
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":60}),
    )
    .await;
    let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
    let old_path = fixture.root.join("r").join(&attachment.ingress_socket);
    let old = aap_client::DaemonSessionClient::new(old_path.clone());
    let operation = fixture.request();
    old.execute(operation.clone())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    child.kill().await.unwrap();
    assert!(old_path.exists(), "crash fixture must leave a stale socket");
    let (mut restarted, new_ready) = fixture.start().await;
    assert_ne!(new_ready.daemon_epoch, ready.daemon_epoch);
    assert_ne!(new_ready.control_socket, ready.control_socket);
    assert!(old.execute(fixture.request()).await.is_err());
    let control = fixture.root.join("r").join(new_ready.control_socket);
    let (_, new_attachment) = local(
        control,
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":60}),
    )
    .await;
    let new_attachment: SessionAttachment = serde_json::from_value(new_attachment).unwrap();
    assert_ne!(new_attachment.session_id, attachment.session_id);
    let new = aap_client::DaemonSessionClient::new(
        fixture.root.join("r").join(new_attachment.ingress_socket),
    );
    assert!(new.request_status(operation.request_id).await.is_err());
    assert_eq!(
        new.execute(fixture.request())
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        "data: [redacted]\n\n"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    stop(&mut restarted).await;
}

#[tokio::test]
async fn expired_session_cannot_dispatch_and_is_pruned_by_control() {
    let fixture = Fixture::new().await;
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(ready.control_socket);
    let (_, attachment) = local(
        control.clone(),
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":1}),
    )
    .await;
    let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
    let path = fixture.root.join("r").join(attachment.ingress_socket);
    let client = aap_client::DaemonSessionClient::new(path.clone());
    client
        .execute(fixture.request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(client.execute(fixture.request()).await.is_err());
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    let (status, state) = local(control, "/aap/operator/v1/status", json!({})).await;
    assert!(status.is_success());
    assert_eq!(state["sessions"], 0);
    assert!(!path.exists());
    stop(&mut child).await;
}

async fn website_fixture() -> Fixture {
    website_fixture_for(aap_types::profile::LoginEncoding::Form).await
}

async fn website_fixture_for(encoding: aap_types::profile::LoginEncoding) -> Fixture {
    website_fixture_for_response(encoding, false).await
}
async fn website_fixture_for_response(
    encoding: aap_types::profile::LoginEncoding,
    redirect: bool,
) -> Fixture {
    use aap_types::{
        CredentialFields,
        profile::{CsrfProfile, LoginEncoding, LoginProfile, LoginSuccess},
    };
    let mut fixture = Fixture::new().await;
    fixture.origin = Origin::with_handler(move |request| {
        let mut reply = match request.target.path() {
            "/login" => { let mut reply = Reply::body(r#"{"csrf":"private-site-csrf","echo":"private-pre"}"#); reply.headers.push(("set-cookie".into(),"pre=private-pre; Secure; Path=/".into())); reply },
            "/session" => {
                match encoding {
                    LoginEncoding::Form => assert_eq!(request.body,"user=private-website-user&password=private-website-password&csrf=private-site-csrf"),
                    LoginEncoding::Json => assert_eq!(serde_json::from_slice::<Value>(&request.body).unwrap(),json!({"user":"private-website-user","password":"private-website-password","csrf":"private-site-csrf"})),
                }
                assert_eq!(request.headers["cookie"],"pre=private-pre");
                let mut reply = Reply::body(r#"{"authenticated":true,"echo":"private-website-password private-website-cookie"}"#);
                if redirect {reply.status=303;reply.headers.push(("location".into(),"/protected".into()));}
                reply.headers.push(("set-cookie".into(),"session=private-website-cookie; Secure; HttpOnly; Path=/".into())); reply
            },
            "/protected" => { assert!(request.headers["cookie"].to_str().unwrap().contains("session=private-website-cookie")); Reply::body(r#"{"data":"protected"}"#) },
            _ => panic!("unexpected website route"),
        }; reply.headers.push(("content-type".into(),"application/json".into())); reply
    }).await;
    let store = SqliteStore::open(
        Arc::new(aap_config::PrivateDir::open(&fixture.root.join("s"), false).unwrap()),
        SecretBytes::new(vec![17; 32]).unwrap(),
        OpenMode::Existing,
        tokio::runtime::Handle::current(),
    )
    .await
    .unwrap();
    let reference = ItemRef::new("private-key-ref".into()).unwrap();
    let metadata = aap_secrets::SecretStore::metadata(&store, &reference)
        .await
        .unwrap();
    store
        .put(
            &reference,
            [
                (
                    Field::Username,
                    SecretBytes::new(b"private-website-user".to_vec()).unwrap(),
                ),
                (
                    Field::Password,
                    SecretBytes::new(b"private-website-password".to_vec()).unwrap(),
                ),
            ]
            .into(),
            Some(&metadata.lease),
        )
        .await
        .unwrap();
    drop(store);
    fixture.config.upstream_roots_der_base64 =
        vec![STANDARD.encode(fixture.origin.certificate.as_ref())];
    let profile = &mut fixture.config.profiles[0];
    profile.origin = fixture.origin.origin();
    profile.addresses = AddressPolicy::Pinned(vec![fixture.origin.address.ip()]);
    profile.routes = [
        ("GET", "/login"),
        ("POST", "/session"),
        ("GET", "/protected"),
    ]
    .into_iter()
    .map(|(method, path)| Route {
        method: method.into(),
        path: path.into(),
        query: None,
        max_request_bytes: 256 * 1024,
        max_response_bytes: 256 * 1024,
        allowed_headers: vec!["content-type".into()],
        streaming: false,
        require_approval: false,
    })
    .collect();
    profile.auth = Authentication::Form {
        login: LoginProfile {
            page: format!("{}/login", fixture.origin.origin()),
            target: format!("{}/session", fixture.origin.origin()),
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
            post_login_redirect: redirect.then(|| format!("{}/protected", fixture.origin.origin())),
            success: LoginSuccess {
                status: if redirect { 303 } else { 200 },
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
    };
    fixture.write();
    fixture
}

#[tokio::test]
async fn standalone_password_manager_keeps_website_sessions_private_and_isolated() {
    use aap_types::{AuthContext, AuthState, GetLogin, SearchItems};
    let fixture = website_fixture().await;
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(ready.control_socket);
    let mut clients = Vec::new();
    for _ in 0..2 {
        let (status, attachment) = local(
            control.clone(),
            "/aap/operator/v1/session/create",
            json!({"resources":["provider"],"items":["key"],"lifetime_seconds":60}),
        )
        .await;
        assert!(status.is_success());
        let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
        clients.push(aap_client::DaemonSessionClient::new(
            fixture.root.join("r").join(attachment.ingress_socket),
        ));
    }
    let uri = format!("{}/login", fixture.origin.origin());
    let search = clients[0]
        .search_items(SearchItems {
            uri: uri.clone(),
            query: None,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(search.items[0].item_id, "key");
    let issue = || GetLogin {
        request_id: aap_types::ids::random_id(16).unwrap(),
        item_id: "key".into(),
        uri: uri.clone(),
    };
    let login = clients[0].get_login(issue()).await.unwrap();
    let other = clients[1].get_login(issue()).await.unwrap();
    assert_ne!(login.auth_context, other.auth_context);
    assert_ne!(
        login.credentials.password.value,
        other.credentials.password.value
    );
    let make_request = |context: &str, method: &str, path: &str, body: &[u8]| ExecuteRequest {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "provider".into(),
        auth_context: Some(context.into()),
        method: method.into(),
        target: format!("{}{path}", fixture.origin.origin()),
        headers: if body.is_empty() {
            vec![]
        } else {
            vec![(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            )]
        },
        body_base64: STANDARD.encode(body),
    };
    let page = clients[0]
        .execute(make_request(&login.auth_context, "GET", "/login", b""))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let page: Value = serde_json::from_slice(&page).unwrap();
    assert_eq!(page["echo"], "[redacted]");
    let body = format!(
        "user={}&password={}&csrf={}",
        login.credentials.username.value,
        login.credentials.password.value,
        page["csrf"].as_str().unwrap()
    );
    let response = clients[0]
        .execute(make_request(
            &login.auth_context,
            "POST",
            "/session",
            body.as_bytes(),
        ))
        .await
        .unwrap();
    assert!(!response.headers().contains_key("set-cookie"));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["echo"],
        "[redacted] [redacted]"
    );
    assert_eq!(
        clients[0]
            .auth_status(AuthContext {
                auth_context: login.auth_context.clone()
            })
            .await
            .unwrap()
            .state,
        AuthState::Authenticated
    );
    let protected = clients[0]
        .execute(make_request(&login.auth_context, "GET", "/protected", b""))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        serde_json::from_slice::<Value>(&protected).unwrap()["data"],
        "protected"
    );
    assert!(
        clients[1]
            .execute(make_request(&login.auth_context, "GET", "/protected", b""))
            .await
            .is_err()
    );
    assert!(
        clients[1]
            .execute(make_request(&other.auth_context, "GET", "/protected", b""))
            .await
            .is_err()
    );
    clients[0]
        .logout(AuthContext {
            auth_context: login.auth_context.clone(),
        })
        .await
        .unwrap();
    assert!(
        clients[0]
            .execute(make_request(&login.auth_context, "GET", "/protected", b""))
            .await
            .is_err()
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    let (_, batch) = local(
        fixture.root.join("r").join(ready.observation_socket),
        "/aap/observe/v1/read",
        json!({"limit":256}),
    )
    .await;
    for record in serde_json::from_value::<aap_observe::Batch>(batch)
        .unwrap()
        .records
    {
        if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
            let bytes = STANDARD.decode(body_base64).unwrap();
            let value = String::from_utf8_lossy(&bytes);
            for private in [
                "private-website-user",
                "private-website-password",
                "private-website-cookie",
                "private-pre",
                "private-site-csrf",
                "aap_pw1_",
                "aap_un1_",
                "aap_cs1_",
            ] {
                assert!(!value.contains(private));
            }
        }
    }
    stop(&mut child).await;
}

struct McpPeer {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: BufReader<tokio::process::ChildStdout>,
    next_id: u64,
}
impl McpPeer {
    async fn start(socket: PathBuf) -> Self {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-auth-proxy"))
            .arg("mcp-bridge")
            .arg(socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut peer = Self {
            child,
            input,
            output,
            next_id: 1,
        };
        peer.send(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})).await;
        assert_eq!(
            peer.receive().await["result"]["protocolVersion"],
            "2025-11-25"
        );
        peer.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        peer
    }
    async fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        self.input.write_all(&bytes).await.unwrap();
    }
    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        let count = tokio::time::timeout(Duration::from_secs(5), self.output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert!(count > 0, "bridge exited without an MCP response");
        serde_json::from_str(&line).unwrap()
    }
    async fn call(&mut self, name: &str, arguments: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await;
        let result = self.receive().await;
        assert_eq!(result["id"], id);
        assert!(result.get("error").is_none());
        let wire = serde_json::to_string(&result).unwrap();
        for secret in [
            "private-website-user",
            "private-website-password",
            "private-website-cookie",
            "private-pre",
            "private-site-csrf",
        ] {
            assert!(!wire.contains(secret));
        }
        result["result"].clone()
    }
    async fn close(mut self) {
        drop(self.input);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), self.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        use tokio::io::AsyncReadExt;
        let mut errors = Vec::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut errors)
            .await
            .unwrap();
        assert!(errors.is_empty(), "bridge emitted non-protocol diagnostics");
    }
}

#[tokio::test]
async fn real_stdio_bridges_complete_private_isolated_website_logins() {
    for encoding in [
        aap_types::profile::LoginEncoding::Form,
        aap_types::profile::LoginEncoding::Json,
    ] {
        stdio_website_flow(encoding).await;
    }
}

async fn stdio_website_flow(encoding: aap_types::profile::LoginEncoding) {
    use aap_types::profile::LoginEncoding;
    let fixture = website_fixture_for(encoding).await;
    let (mut daemon, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(ready.control_socket);
    let uri = format!("{}/login", fixture.origin.origin());
    let mut peers = Vec::new();
    let mut logins = Vec::new();
    for _ in 0..2 {
        let (status, attachment) = local(
            control.clone(),
            "/aap/operator/v1/session/create",
            json!({"resources":["provider"],"items":["key"],"lifetime_seconds":60}),
        )
        .await;
        assert!(status.is_success());
        let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
        let mut peer = McpPeer::start(fixture.root.join("r").join(attachment.ingress_socket)).await;
        let search = peer.call("vault.search_items", json!({"uri":uri})).await;
        assert_eq!(search["structuredContent"]["items"][0]["item_id"], "key");
        let login=peer.call("vault.get_login",json!({"request_id":aap_types::ids::random_id(16).unwrap(),"item_id":"key","uri":uri})).await;
        assert_eq!(login["isError"], false);
        logins.push(login["structuredContent"].clone());
        peers.push(peer);
    }
    assert_ne!(logins[0]["auth_context"], logins[1]["auth_context"]);
    let request = |context: &Value, method: &str, path: &str, body: &[u8]| {
        json!({
            "request_id":aap_types::ids::random_id(16).unwrap(),"resource":"provider","auth_context":context,"method":method,"target":format!("{}{path}",fixture.origin.origin()),
            "headers":if body.is_empty(){json!([])}else{json!([["content-type",if encoding==LoginEncoding::Form {"application/x-www-form-urlencoded"} else {"application/json"}]])},"body_base64":STANDARD.encode(body)
        })
    };
    for (peer, login) in peers.iter_mut().zip(&logins) {
        let context = &login["auth_context"];
        let page = peer
            .call("request.execute", request(context, "GET", "/login", b""))
            .await;
        let page: Value = serde_json::from_slice(
            &STANDARD
                .decode(page["structuredContent"]["body_base64"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(page["echo"], "[redacted]");
        let form = if encoding == LoginEncoding::Json {
            json!({"user":login["credentials"]["username"]["value"],"password":login["credentials"]["password"]["value"],"csrf":page["csrf"]}).to_string()
        } else {
            format!(
                "user={}&password={}&csrf={}",
                login["credentials"]["username"]["value"].as_str().unwrap(),
                login["credentials"]["password"]["value"].as_str().unwrap(),
                page["csrf"].as_str().unwrap()
            )
        };
        let result = peer
            .call(
                "request.execute",
                request(context, "POST", "/session", form.as_bytes()),
            )
            .await;
        assert_eq!(result["isError"], false);
        let body: Value = serde_json::from_slice(
            &STANDARD
                .decode(result["structuredContent"]["body_base64"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["echo"], "[redacted] [redacted]");
        let status = peer
            .call("vault.auth_status", json!({"auth_context":context}))
            .await;
        assert_eq!(status["structuredContent"]["state"], "authenticated");
        let protected = request(context, "GET", "/protected", b"");
        let request_id = protected["request_id"].clone();
        let response = peer.call("request.execute", protected.clone()).await;
        let bytes = STANDARD
            .decode(
                response["structuredContent"]["body_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["data"],
            "protected"
        );
        assert_eq!(
            peer.call("request.execute", protected).await["structuredContent"]["kind"],
            "operation"
        );
        assert_eq!(
            peer.call("request.status", json!({"request_id":request_id}))
                .await["structuredContent"]["state"],
            "completed"
        );
    }
    assert_eq!(
        peers[1]
            .call(
                "request.execute",
                request(&logins[0]["auth_context"], "GET", "/protected", b"")
            )
            .await["isError"],
        true
    );
    for (mut peer, login) in peers.into_iter().zip(logins) {
        let context = &login["auth_context"];
        assert_eq!(
            peer.call("vault.logout", json!({"auth_context":context}))
                .await["structuredContent"]["state"],
            "revoked"
        );
        assert_eq!(
            peer.call(
                "request.execute",
                request(context, "GET", "/protected", b"")
            )
            .await["isError"],
            true
        );
        peer.close().await;
    }
    assert_eq!(
        fixture.origin.requests.lock().unwrap().len(),
        6,
        "duplicate or denied MCP work was dispatched"
    );
    let (_, batch) = local(
        fixture.root.join("r").join(ready.observation_socket),
        "/aap/observe/v1/read",
        json!({"limit":512}),
    )
    .await;
    for record in serde_json::from_value::<aap_observe::Batch>(batch)
        .unwrap()
        .records
    {
        if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
            let bytes = STANDARD.decode(body_base64).unwrap();
            let value = String::from_utf8_lossy(&bytes);
            for private in [
                "private-website-user",
                "private-website-password",
                "private-website-cookie",
                "private-pre",
                "private-site-csrf",
                "aap_pw1_",
                "aap_un1_",
                "aap_cs1_",
            ] {
                assert!(!value.contains(private));
            }
        }
    }
    stop(&mut daemon).await;
}
