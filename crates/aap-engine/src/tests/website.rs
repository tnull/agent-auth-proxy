use super::vault::{issuance, website_configuration};
use super::*;
use aap_types::profile::LoginEncoding;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

fn website_origin(encoding: LoginEncoding, successful: bool) -> impl Future<Output = Origin> {
    website_origin_redirect(encoding, successful, 200, None)
}
fn website_origin_redirect(
    encoding: LoginEncoding,
    successful: bool,
    status: u16,
    location: Option<&'static str>,
) -> impl Future<Output = Origin> {
    Origin::with_handler(move |request| {
        let mut reply = match request.target.path() {
            "/login" => {
                let mut reply = Reply::body(r#"{"csrf":"private-csrf","echo":"private-pre"}"#);
                reply.headers.push((
                    "set-cookie".into(),
                    "pre=private-pre; Secure; HttpOnly; Path=/; SameSite=Strict".into(),
                ));
                reply
            }
            "/session" => {
                assert!(
                    request.headers["cookie"]
                        .to_str()
                        .unwrap()
                        .contains("pre=private-pre")
                );
                match encoding {
                    LoginEncoding::Form => assert_eq!(
                        request.body,
                        "user=private-user&password=private-password&csrf=private-csrf"
                    ),
                    LoginEncoding::Json => assert_eq!(
                        serde_json::from_slice::<Value>(&request.body).unwrap(),
                        json!({"user":"private-user","password":"private-password","csrf":"private-csrf"})
                    ),
                }
                let mut reply = Reply::body(json!({"authenticated":successful,"echo":"private-password private-user private-session private-csrf"}).to_string());
                reply.status = status;
                if let Some(location) = location {
                    reply.headers.push(("location".into(), location.into()));
                }
                reply.headers.push((
                    "set-cookie".into(),
                    "session=private-session; Secure; HttpOnly; Path=/".into(),
                ));
                reply
            }
            "/protected" | "/action" => {
                assert!(
                    request.headers["cookie"]
                        .to_str()
                        .unwrap()
                        .contains("session=private-session")
                );
                Reply::body(r#"{"data":"protected","echo":"private-password private-session"}"#)
            }
            _ => panic!("unexpected fixture route"),
        };
        reply
            .headers
            .push(("content-type".into(), "application/json".into()));
        reply
    })
}

#[tokio::test]
async fn enrolled_login_redirects_keep_next_get_independent_and_never_repeat_passwords() {
    for (status, location, successful, requires_approval, allowed) in [
        (303, "/protected", true, false, true),
        (303, "/protected", true, true, true),
        (303, "https://other.test/protected", true, false, false),
        (
            303,
            "/protected?password=private-password",
            true,
            false,
            false,
        ),
        (307, "/protected", true, false, false),
        (308, "/protected", true, false, false),
        (303, "/protected", false, false, false),
    ] {
        let mut fixture = Fixture::new().await;
        fixture.origin =
            website_origin_redirect(LoginEncoding::Form, successful, status, Some(location)).await;
        let mut configuration = website_configuration(&fixture, LoginEncoding::Form).await;
        let target = format!("{}/protected", fixture.origin.origin());
        let Authentication::Form { login } = &mut configuration.profiles[0].auth else {
            unreachable!()
        };
        login.post_login_redirect = Some(target.clone());
        login.success.status = 303;
        configuration.profiles[0]
            .routes
            .iter_mut()
            .find(|route| route.path == "/protected")
            .unwrap()
            .require_approval = requires_approval;
        let broker = Broker::new(configuration).unwrap();
        let session = broker.create_session(options()).unwrap();
        let login = session.get_login(issuance(&fixture)).await.unwrap();
        let csrf = page(&fixture, &session, &login).await;
        let input = request(
            &fixture,
            &login,
            "POST",
            "/session",
            &login_body(&login, &csrf, LoginEncoding::Form),
        );
        let result = session.execute(input).await;
        if allowed {
            let response = result.expect("enrolled successful 303 login was refused");
            assert_eq!(response.status(), 303);
            assert_eq!(response.headers()["location"], target);
            assert!(!response.headers().contains_key("set-cookie"));
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap()["echo"],
                "[redacted] [redacted] [redacted] [redacted]"
            );
            assert_eq!(
                fixture.origin.requests.lock().unwrap().len(),
                2,
                "redirect automatically dispatched another request"
            );
            assert_eq!(
                session
                    .auth_status(AuthContext {
                        auth_context: login.auth_context.clone()
                    })
                    .await
                    .unwrap()
                    .state,
                AuthState::Authenticated
            );
            let follow = session
                .execute(request(&fixture, &login, "GET", "/protected", b""))
                .await;
            if requires_approval {
                assert!(
                    matches!(follow,Err(error) if error.code==ErrorCode::InteractionUnavailable)
                );
                assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
            } else {
                let body = follow
                    .unwrap()
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
                assert_eq!(
                    serde_json::from_slice::<Value>(&body).unwrap()["data"],
                    "protected"
                );
                let requests = fixture.origin.requests.lock().unwrap();
                assert_eq!(requests.len(), 3);
                assert!(requests[2].body.is_empty());
                assert_eq!(requests[2].method, "GET");
            }
        } else {
            assert!(
                result.is_err(),
                "unsafe or unsuccessful redirect accepted: {status} {location}"
            );
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
            assert_ne!(
                session
                    .auth_status(AuthContext {
                        auth_context: login.auth_context.clone()
                    })
                    .await
                    .unwrap()
                    .state,
                AuthState::Authenticated
            );
        }
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
    }
}
fn request(
    fixture: &Fixture,
    login: &Login,
    method: &str,
    path: &str,
    body: &[u8],
) -> ExecuteRequest {
    ExecuteRequest {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "provider".into(),
        auth_context: Some(login.auth_context.clone()),
        method: method.into(),
        target: format!("{}{path}", fixture.origin.origin()),
        headers: if body.is_empty() {
            vec![]
        } else {
            vec![("content-type".into(), login.submission.content_type.clone())]
        },
        body_base64: STANDARD.encode(body),
    }
}
async fn page(fixture: &Fixture, session: &Session, login: &Login) -> String {
    let response = session
        .execute(request(fixture, login, "GET", "/login", b""))
        .await
        .expect("website page refused");
    assert!(!response.headers().contains_key("set-cookie"));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["echo"], "[redacted]");
    let token = page["csrf"].as_str().unwrap().to_owned();
    assert!(token.starts_with("aap_cs1_"));
    token
}
fn login_body(login: &Login, csrf: &str, encoding: LoginEncoding) -> Vec<u8> {
    match encoding {
        LoginEncoding::Form => format!("user={}&password={}&csrf={csrf}",login.credentials.username.value,login.credentials.password.value).into_bytes(),
        LoginEncoding::Json => serde_json::to_vec(&json!({"user":login.credentials.username.value,"password":login.credentials.password.value,"csrf":csrf})).unwrap(),
    }
}

#[tokio::test]
async fn fake_form_and_json_logins_reach_protected_pages_without_exposing_secrets() {
    for encoding in [LoginEncoding::Form, LoginEncoding::Json] {
        let mut fixture = Fixture::new().await;
        fixture.origin = website_origin(encoding, true).await;
        let broker = Broker::new(website_configuration(&fixture, encoding).await).unwrap();
        let session = broker.create_session(options()).unwrap();
        let login = session.get_login(issuance(&fixture)).await.unwrap();
        let csrf = page(&fixture, &session, &login).await;
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        let input = request(
            &fixture,
            &login,
            "POST",
            "/session",
            &login_body(&login, &csrf, encoding),
        );
        let response = session
            .execute(input.clone())
            .await
            .expect("fake login refused");
        assert!(!response.headers().contains_key("set-cookie"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["echo"],
            "[redacted] [redacted] [redacted] [redacted]"
        );
        assert_eq!(
            session
                .auth_status(AuthContext {
                    auth_context: login.auth_context.clone()
                })
                .await
                .unwrap()
                .state,
            AuthState::Authenticated
        );
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
        let protected = session
            .execute(request(&fixture, &login, "GET", "/protected", b""))
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
        assert_eq!(
            serde_json::from_slice::<Value>(&protected).unwrap()["echo"],
            "[redacted] [redacted]"
        );
        assert_eq!(
            fixture.resolutions.load(Ordering::SeqCst),
            1,
            "cookie access unnecessarily resolved the password"
        );
        assert_eq!(
            session.execute(input).await.unwrap().headers()["x-aap-operation-state"],
            "existing"
        );
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
        for record in fixture.recorder.read(None, 256).unwrap().records {
            if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
                let bytes = STANDARD.decode(body_base64).unwrap();
                let content = String::from_utf8_lossy(&bytes);
                for private in [
                    "private-password",
                    "private-user",
                    "private-session",
                    "private-pre",
                    "private-csrf",
                    "aap_pw1_",
                    "aap_un1_",
                    "aap_cs1_",
                ] {
                    assert!(!content.contains(private), "observation leaked {private}");
                }
            }
        }
        session
            .logout(AuthContext {
                auth_context: login.auth_context.clone(),
            })
            .await
            .unwrap();
        assert!(
            session
                .execute(request(&fixture, &login, "GET", "/protected", b""))
                .await
                .is_err()
        );
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    }
}

#[tokio::test]
async fn invalid_placeholders_and_unsuccessful_login_cannot_establish_cookie_authority() {
    let encoding = LoginEncoding::Form;
    let mut fixture = Fixture::new().await;
    fixture.origin = website_origin(encoding, false).await;
    let broker = Broker::new(website_configuration(&fixture, encoding).await).unwrap();
    let session = broker.create_session(options()).unwrap();
    let other = broker.create_session(options()).unwrap();
    let login = session.get_login(issuance(&fixture)).await.unwrap();
    let csrf = page(&fixture, &session, &login).await;
    assert!(
        other
            .execute(request(&fixture, &login, "GET", "/protected", b""))
            .await
            .is_err()
    );
    let mut bad = login_body(&login, &csrf, encoding);
    bad.extend_from_slice(b"&password=duplicate");
    assert!(
        session
            .execute(request(&fixture, &login, "POST", "/session", &bad))
            .await
            .is_err()
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    let response = session
        .execute(request(
            &fixture,
            &login,
            "POST",
            "/session",
            &login_body(&login, &csrf, encoding),
        ))
        .await
        .unwrap();
    response.into_body().collect().await.unwrap();
    assert_eq!(
        session
            .auth_status(AuthContext {
                auth_context: login.auth_context.clone()
            })
            .await
            .unwrap()
            .state,
        AuthState::Unauthenticated
    );
    assert!(
        session
            .execute(request(&fixture, &login, "GET", "/protected", b""))
            .await
            .is_err()
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn login_approval_holds_no_password_and_rejects_late_rotation_or_logout() {
    for change in ["none", "rotate", "logout"] {
        let encoding = LoginEncoding::Form;
        let mut fixture = Fixture::new().await;
        fixture.origin = website_origin(encoding, true).await;
        let mut configuration = website_configuration(&fixture, encoding).await;
        configuration.catalog.items[0].approval = ItemApproval::Authenticate;
        let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
        let (decision, answer) = tokio::sync::oneshot::channel();
        configuration.approval = Some(Arc::new(Gate {
            received: sent,
            decision: Mutex::new(Some(answer)),
        }));
        let broker = Broker::new(configuration).unwrap();
        let session = broker.create_session(options()).unwrap();
        let login = session.get_login(issuance(&fixture)).await.unwrap();
        let csrf = page(&fixture, &session, &login).await;
        let input = request(
            &fixture,
            &login,
            "POST",
            "/session",
            &login_body(&login, &csrf, encoding),
        );
        let frozen = input.clone();
        let running = session.clone();
        let execution = tokio::spawn(async move { running.execute(input).await });
        let approval = tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(*approval.operation == frozen);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(
            session
                .request_status(frozen.request_id)
                .await
                .unwrap()
                .state,
            OperationState::PendingApproval
        );
        assert!(
            matches!(session.execute(request(&fixture,&login,"GET","/login",b"")).await,Err(error) if error.code == ErrorCode::AuthInProgress)
        );
        assert_eq!(
            session
                .auth_status(AuthContext {
                    auth_context: login.auth_context.clone()
                })
                .await
                .unwrap()
                .state,
            AuthState::Authenticating
        );
        if change == "rotate" {
            fixture
                .store
                .put(
                    &ItemRef::new("private-reference".into()).unwrap(),
                    [
                        (
                            Field::Username,
                            SecretBytes::new(b"changed-user".to_vec()).unwrap(),
                        ),
                        (
                            Field::Password,
                            SecretBytes::new(b"changed-password".to_vec()).unwrap(),
                        ),
                    ]
                    .into(),
                    Some(&approval.credential_lease),
                )
                .await
                .unwrap();
        } else if change == "logout" {
            session
                .logout(AuthContext {
                    auth_context: login.auth_context.clone(),
                })
                .await
                .unwrap();
        }
        let _ = decision.send(true);
        let result = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .unwrap()
            .unwrap();
        if change == "none" {
            result.unwrap().into_body().collect().await.unwrap();
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
        } else {
            assert!(result.is_err());
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn cookie_authentication_cannot_bypass_action_approval_or_a_locked_store() {
    for locked in [false, true] {
        let encoding = LoginEncoding::Json;
        let mut fixture = Fixture::new().await;
        fixture.origin = website_origin(encoding, true).await;
        let mut configuration = website_configuration(&fixture, encoding).await;
        if !locked {
            configuration.profiles[0]
                .routes
                .iter_mut()
                .find(|route| route.path == "/protected")
                .unwrap()
                .require_approval = true;
        }
        let broker = Broker::new(configuration).unwrap();
        let session = broker.create_session(options()).unwrap();
        let login = session.get_login(issuance(&fixture)).await.unwrap();
        let csrf = page(&fixture, &session, &login).await;
        session
            .execute(request(
                &fixture,
                &login,
                "POST",
                "/session",
                &login_body(&login, &csrf, encoding),
            ))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        if locked {
            fixture.store.lock().await.unwrap();
        }
        let result = session
            .execute(request(&fixture, &login, "GET", "/protected", b""))
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("protected request bypassed approval/store state"),
        };
        assert_eq!(
            error.code,
            if locked {
                ErrorCode::VaultLocked
            } else {
                ErrorCode::InteractionUnavailable
            }
        );
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn login_attempt_budget_survives_new_contexts_and_csrf_placeholders_rotate() {
    let encoding = LoginEncoding::Form;
    let mut fixture = Fixture::new().await;
    fixture.origin = website_origin(encoding, true).await;
    let broker = Broker::new(website_configuration(&fixture, encoding).await).unwrap();
    let session = broker.create_session(options()).unwrap();
    for attempt in 0..6 {
        let login = session.get_login(issuance(&fixture)).await.unwrap();
        let csrf = page(&fixture, &session, &login).await;
        let csrf = if attempt == 0 {
            let next = page(&fixture, &session, &login).await;
            assert_ne!(csrf, next);
            assert!(
                session
                    .execute(request(
                        &fixture,
                        &login,
                        "POST",
                        "/session",
                        &login_body(&login, &csrf, encoding)
                    ))
                    .await
                    .is_err()
            );
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
            next
        } else {
            csrf
        };
        let result = session
            .execute(request(
                &fixture,
                &login,
                "POST",
                "/session",
                &login_body(&login, &csrf, encoding),
            ))
            .await;
        if attempt < 5 {
            result.unwrap().into_body().collect().await.unwrap();
            session
                .logout(AuthContext {
                    auth_context: login.auth_context,
                })
                .await
                .unwrap();
        } else {
            assert!(matches!(result,Err(error) if error.code == ErrorCode::LimitExceeded));
        }
    }
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 5);
    assert_eq!(
        fixture
            .origin
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.target.path() == "/session")
            .count(),
        5
    );
}

#[tokio::test]
async fn uncertain_login_invalidates_the_context_and_never_retries() {
    let mut fixture = Fixture::new().await;
    fixture.origin = Origin::with_handler(|request| {
        let mut reply = Reply::body(r#"{"csrf":"private-csrf","echo":"private-pre"}"#);
        reply
            .headers
            .push(("content-type".into(), "application/json".into()));
        if request.target.path() == "/login" {
            reply.headers.push((
                "set-cookie".into(),
                "pre=private-pre; Secure; Path=/".into(),
            ));
        } else {
            assert_eq!(request.target.path(), "/session");
            reply.disconnect = true;
        }
        reply
    })
    .await;
    let encoding = LoginEncoding::Form;
    let broker = Broker::new(website_configuration(&fixture, encoding).await).unwrap();
    let session = broker.create_session(options()).unwrap();
    let login = session.get_login(issuance(&fixture)).await.unwrap();
    let csrf = page(&fixture, &session, &login).await;
    let input = request(
        &fixture,
        &login,
        "POST",
        "/session",
        &login_body(&login, &csrf, encoding),
    );
    assert!(
        matches!(session.execute(input.clone()).await,Err(error) if error.code == ErrorCode::OutcomeUnknown)
    );
    assert_eq!(
        session
            .request_status(input.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::OutcomeUnknown
    );
    assert_eq!(
        session.execute(input).await.unwrap().headers()["x-aap-operation-state"],
        "existing"
    );
    assert_eq!(
        session
            .auth_status(AuthContext {
                auth_context: login.auth_context.clone()
            })
            .await
            .unwrap()
            .state,
        AuthState::Revoked
    );
    assert!(
        session
            .execute(request(&fixture, &login, "GET", "/protected", b""))
            .await
            .is_err()
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
}
