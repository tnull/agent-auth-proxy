use super::*;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::AsyncReadExt;

pub(super) async fn enroll_ca(fixture: &mut Fixture) -> CertificateDer<'static> {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
    let certificate = params.self_signed(&key).unwrap().der().clone();
    let store = SqliteStore::open(
        Arc::new(aap_config::PrivateDir::open(&fixture.root.join("s"), false).unwrap()),
        SecretBytes::new(vec![17; 32]).unwrap(),
        OpenMode::Existing,
        tokio::runtime::Handle::current(),
    )
    .await
    .unwrap();
    store
        .put(
            &ItemRef::new("private-ca-reference".into()).unwrap(),
            [(
                Field::PrivateKey,
                SecretBytes::new(key.serialize_der()).unwrap(),
            )]
            .into(),
            None,
        )
        .await
        .unwrap();
    fixture.config.interception = Some(InterceptionConfiguration {
        certificate_der_base64: STANDARD.encode(certificate.as_ref()),
        credential: CredentialRef {
            store: "default".into(),
            key: "private-ca-reference".into(),
        },
    });
    fixture.write();
    certificate
}

async fn connect(socket: &std::path::Path, authority: &str) -> (tokio::net::UnixStream, String) {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), async {
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            assert!(response.len() < 8192);
            response.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(response).unwrap()
    })
    .await
    .unwrap();
    (stream, response)
}
async fn tunnel(
    socket: &std::path::Path,
    authority: &str,
    root: CertificateDer<'static>,
    name: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::UnixStream>> {
    let (stream, response) = connect(socket, authority).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "CONNECT was not admitted: {response}"
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name.to_owned()).unwrap(), stream),
    )
    .await
    .unwrap()
}
pub(super) async fn request(
    socket: &std::path::Path,
    authority: &str,
    root: CertificateDer<'static>,
    request: http::Request<Full<Bytes>>,
) -> (http::StatusCode, http::HeaderMap, Bytes) {
    let tls = tunnel(socket, authority, root, "fixture.test")
        .await
        .unwrap();
    request_on_tunnel(tls, request).await
}
async fn request_on_tunnel(
    tls: tokio_rustls::client::TlsStream<tokio::net::UnixStream>,
    request: http::Request<Full<Bytes>>,
) -> (http::StatusCode, http::HeaderMap, Bytes) {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = tokio::time::timeout(Duration::from_secs(3), sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let (parts, body) = response.into_parts();
    let body = tokio::time::timeout(Duration::from_secs(3), body.collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    driver.abort();
    for secret in [
        "private-website-password",
        "private-website-user",
        "private-website-cookie",
        "private-pre",
        "private-site-csrf",
        "synthetic-daemon-key",
    ] {
        assert!(
            !String::from_utf8_lossy(&body).contains(secret),
            "secret appeared in downstream body"
        );
    }
    assert!(!parts.headers.contains_key("set-cookie"));
    (parts.status, parts.headers, body)
}
pub(super) fn http_request(
    method: &str,
    path: &str,
    host: &str,
    content_type: &str,
    body: Bytes,
) -> http::Request<Full<Bytes>> {
    http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("content-type", content_type)
        .header("connection", "close")
        .body(Full::new(body))
        .unwrap()
}

#[tokio::test]
async fn connect_rechecks_ca_rotation_and_independent_upstream_trust() {
    use aap_secrets::SecretStore;
    let mut fixture = Fixture::new().await;
    let root = enroll_ca(&mut fixture).await;
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(&ready.control_socket);
    let (_, attachment) = local(
        control.clone(),
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":60}),
    )
    .await;
    let socket = fixture
        .root
        .join("r")
        .join(attachment["ingress_socket"].as_str().unwrap());
    let authority = format!("fixture.test:{}", fixture.origin.address.port());
    let original = fixture.request();
    let provider_request = || {
        http_request(
            "POST",
            "/v1/chat/completions",
            &authority,
            "application/json",
            STANDARD.decode(&original.body_base64).unwrap().into(),
        )
    };
    assert_eq!(
        request(&socket, &authority, root.clone(), provider_request())
            .await
            .0,
        200
    );
    let established = tunnel(&socket, &authority, root.clone(), "fixture.test")
        .await
        .unwrap();
    let store = SqliteStore::open(
        Arc::new(aap_config::PrivateDir::open(&fixture.root.join("s"), false).unwrap()),
        SecretBytes::new(vec![17; 32]).unwrap(),
        OpenMode::Existing,
        tokio::runtime::Handle::current(),
    )
    .await
    .unwrap();
    let reference = ItemRef::new("private-ca-reference".into()).unwrap();
    let metadata = store.metadata(&reference).await.unwrap();
    let snapshot = store.resolve(&reference, &metadata.lease).await.unwrap();
    let updated = store
        .put(
            &reference,
            [(
                Field::PrivateKey,
                SecretBytes::new(snapshot.field(Field::PrivateKey).unwrap().expose().to_vec())
                    .unwrap(),
            )]
            .into(),
            Some(&metadata.lease),
        )
        .await
        .unwrap();
    assert_eq!(
        request_on_tunnel(established, provider_request()).await.0,
        503,
        "old CA lease remained usable inside an established TLS connection"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert_eq!(
        request(&socket, &authority, root.clone(), provider_request())
            .await
            .0,
        200
    );
    store
        .put(
            &reference,
            [(
                Field::PrivateKey,
                SecretBytes::new(rcgen::KeyPair::generate().unwrap().serialize_der()).unwrap(),
            )]
            .into(),
            Some(&updated.lease),
        )
        .await
        .unwrap();
    let (_, refused) = connect(&socket, &authority).await;
    assert!(
        refused.starts_with("HTTP/1.1 503"),
        "mismatched CA key was accepted"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    stop(&mut child).await;

    let mut fixture = Fixture::new().await;
    let root = enroll_ca(&mut fixture).await;
    let unrelated = Origin::spawn(Reply::body("unrelated")).await;
    fixture.config.upstream_roots_der_base64 =
        vec![STANDARD.encode(unrelated.certificate.as_ref())];
    fixture.write();
    let (mut child, ready) = fixture.start().await;
    let (_, attachment) = local(
        fixture.root.join("r").join(ready.control_socket),
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":60}),
    )
    .await;
    let socket = fixture
        .root
        .join("r")
        .join(attachment["ingress_socket"].as_str().unwrap());
    let authority = format!("fixture.test:{}", fixture.origin.address.port());
    let original = fixture.request();
    assert_eq!(
        request(
            &socket,
            &authority,
            root,
            http_request(
                "POST",
                "/v1/chat/completions",
                &authority,
                "application/json",
                STANDARD.decode(original.body_base64).unwrap().into()
            )
        )
        .await
        .0,
        503
    );
    assert!(
        fixture.origin.requests.lock().unwrap().is_empty(),
        "interception trust bypassed independent upstream trust"
    );
    stop(&mut child).await;
}

#[tokio::test]
async fn connect_proxy_brokers_provider_and_rejects_virtual_host_escape() {
    let mut fixture = Fixture::new().await;
    let root = enroll_ca(&mut fixture).await;
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(ready.control_socket);
    let (_, attachment) = local(
        control,
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":60}),
    )
    .await;
    let socket = fixture
        .root
        .join("r")
        .join(attachment["ingress_socket"].as_str().unwrap());
    let authority = format!("fixture.test:{}", fixture.origin.address.port());
    let original = fixture.request();
    let (status, _, body) = request(
        &socket,
        &authority,
        root.clone(),
        http_request(
            "POST",
            "/v1/chat/completions",
            &authority,
            "application/json",
            STANDARD.decode(original.body_base64).unwrap().into(),
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, "data: [redacted]\n\n");
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert_eq!(
        fixture.origin.requests.lock().unwrap()[0].headers["authorization"],
        "Bearer synthetic-daemon-key"
    );
    let (status, _, _) = request(
        &socket,
        &authority,
        root.clone(),
        http_request(
            "POST",
            "/v1/chat/completions",
            "other.test",
            "application/json",
            Bytes::from_static(b"{}"),
        ),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert!(
        tunnel(&socket, &authority, root, "other.test")
            .await
            .is_err()
    );
    let (_, denied) = connect(&socket, "other.test:443").await;
    assert!(denied.starts_with("HTTP/1.1 403"));
    stop(&mut child).await;
}

#[tokio::test]
async fn connect_website_uses_only_a_unique_prepared_context() {
    for redirect in [false, true] {
        website_context_flow(redirect).await;
    }
}
async fn website_context_flow(redirect: bool) {
    use aap_types::{AuthContext, AuthState, GetLogin};
    let mut fixture =
        website_fixture_for_response(aap_types::profile::LoginEncoding::Form, redirect).await;
    let root = enroll_ca(&mut fixture).await;
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(ready.control_socket);
    let (_, attachment) = local(
        control,
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"items":["key"],"lifetime_seconds":60}),
    )
    .await;
    let socket = fixture
        .root
        .join("r")
        .join(attachment["ingress_socket"].as_str().unwrap());
    let client = aap_client::DaemonSessionClient::new(socket.clone());
    let authority = format!("fixture.test:{}", fixture.origin.address.port());
    let get = || {
        http_request(
            "GET",
            "/login",
            &authority,
            "application/json",
            Bytes::new(),
        )
    };
    assert_eq!(
        request(&socket, &authority, root.clone(), get()).await.0,
        403
    );
    let login = client
        .get_login(GetLogin {
            request_id: aap_types::ids::random_id(16).unwrap(),
            item_id: "key".into(),
            uri: format!("{}/login", fixture.origin.origin()),
        })
        .await
        .unwrap();
    let (status, _, page) = request(&socket, &authority, root.clone(), get()).await;
    assert_eq!(status, 200);
    let page: Value = serde_json::from_slice(&page).unwrap();
    let body = format!(
        "user={}&password={}&csrf={}",
        login.credentials.username.value,
        login.credentials.password.value,
        page["csrf"].as_str().unwrap()
    );
    let (status, headers, _) = request(
        &socket,
        &authority,
        root.clone(),
        http_request(
            "POST",
            "/session",
            &authority,
            "application/x-www-form-urlencoded",
            body.into(),
        ),
    )
    .await;
    assert_eq!(status, if redirect { 303 } else { 200 });
    if redirect {
        assert_eq!(
            headers["location"],
            format!("{}/protected", fixture.origin.origin())
        );
    }
    assert_eq!(
        fixture.origin.requests.lock().unwrap().len(),
        2,
        "redirect dispatched another upstream action"
    );
    assert_eq!(
        client
            .auth_status(AuthContext {
                auth_context: login.auth_context.clone()
            })
            .await
            .unwrap()
            .state,
        AuthState::Authenticated
    );
    let (status, _, body) = request(
        &socket,
        &authority,
        root.clone(),
        http_request(
            "GET",
            "/protected",
            &authority,
            "application/json",
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(status, 200);
    {
        let requests = fixture.origin.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[2].method, "GET");
        assert!(requests[2].body.is_empty());
    }
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["data"],
        "protected"
    );
    let _second = client
        .get_login(GetLogin {
            request_id: aap_types::ids::random_id(16).unwrap(),
            item_id: "key".into(),
            uri: format!("{}/login", fixture.origin.origin()),
        })
        .await
        .unwrap();
    let count = fixture.origin.requests.lock().unwrap().len();
    assert_eq!(
        request(&socket, &authority, root.clone(), get()).await.0,
        403
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), count);
    let mut explicit = get();
    explicit
        .headers_mut()
        .insert("proxy-auth-context", login.auth_context.parse().unwrap());
    assert_eq!(request(&socket, &authority, root, explicit).await.0, 200);
    assert!(
        fixture
            .origin
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.headers.contains_key("proxy-auth-context"))
    );
    stop(&mut child).await;
}
