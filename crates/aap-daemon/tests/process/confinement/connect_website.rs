use super::{
    boundary::Boundary,
    connect::*,
    website::{success, tool},
    *,
};
use aap_types::{AuthContext, GetLogin, Login, profile::LoginEncoding};

#[tokio::test]
#[ignore = "requires the explicit Linux confinement setup in docs/confinement.md"]
async fn confined_connect_keeps_website_passwords_cookies_and_redirects_private() {
    let _exclusive = LAUNCH_TEST_LOCK.lock().await;
    for encoding in [LoginEncoding::Form, LoginEncoding::Json] {
        website(encoding).await;
    }
}

async fn website(encoding: LoginEncoding) {
    let mut fixture = website_fixture_for_response(encoding, true).await;
    let root = super::super::interception::enroll_ca(&mut fixture).await;
    let (mut daemon, ready) = fixture.start().await;
    let boundary = Boundary::new(
        &fixture,
        &daemon,
        &ready,
        json!({"resources":["provider"],"items":["key"],"lifetime_seconds":120}),
        &[fixture.origin.address],
    )
    .await;
    connections(&fixture, 2).await;
    let mut processes = [boundary.spawn(0).await, boundary.spawn(1).await];
    let page = action(&fixture, &root, "GET", "/login", "application/json", vec![]);
    let protected = action(
        &fixture,
        &root,
        "GET",
        "/protected",
        "application/json",
        vec![],
    );
    response(
        &boundary.action(&mut processes[0], 0, page.clone()).await,
        403,
    );
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    let mut logins = vec![];
    for (index, process) in processes.iter_mut().enumerate() {
        let login: Login = serde_json::from_value(success(
            tool(
                &boundary,
                process,
                index,
                "vault.get_login",
                GetLogin {
                    request_id: aap_types::ids::random_id(16).unwrap(),
                    item_id: "key".into(),
                    uri: format!("{}/login", fixture.origin.origin()),
                },
            )
            .await,
        ))
        .unwrap();
        assert!(login.credentials.username.value.starts_with("aap_un1_"));
        assert!(login.credentials.password.value.starts_with("aap_pw1_"));
        let bytes = response(&boundary.action(process, index, page.clone()).await, 200);
        let metadata: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(metadata["echo"], "[redacted]");
        let csrf = metadata["csrf"].as_str().unwrap();
        assert!(csrf.starts_with("aap_cs1_"));
        let (content_type, body) = if encoding == LoginEncoding::Form {
            (
                "application/x-www-form-urlencoded",
                format!(
                    "user={}&password={}&csrf={csrf}",
                    login.credentials.username.value, login.credentials.password.value
                )
                .into_bytes(),
            )
        } else {
            ("application/json", serde_json::to_vec(&json!({"user":login.credentials.username.value,"password":login.credentials.password.value,"csrf":csrf})).unwrap())
        };
        let submitted = boundary
            .action(
                process,
                index,
                action(&fixture, &root, "POST", "/session", content_type, body),
            )
            .await;
        response(&submitted, 303);
        assert!(
            submitted["headers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|header| header
                    == &json!(["location", format!("{}/protected", fixture.origin.origin())]))
        );
        assert_eq!(
            fixture.origin.requests.lock().unwrap().len(),
            index * 3 + 2,
            "redirect must not issue an implicit authenticated follow-up"
        );
        let body = response(
            &boundary.action(process, index, protected.clone()).await,
            200,
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["data"],
            "protected"
        );
        logins.push(login);
    }
    assert_ne!(logins[0].auth_context, logins[1].auth_context);
    assert_ne!(
        logins[0].credentials.password.value,
        logins[1].credentials.password.value
    );
    for (index, process) in processes.iter_mut().enumerate() {
        let mut crossed = protected.clone();
        crossed["request"]["headers"]
            .as_array_mut()
            .unwrap()
            .push(json!([
                "proxy-auth-context",
                logins[1 - index].auth_context
            ]));
        // A valid handle from another session has no binding here: deny
        // authority, rather than reporting a malformed placeholder.
        let bytes = response(&boundary.action(process, index, crossed).await, 403);
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["code"],
            "policy_denied"
        );
    }
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 6);
    success(
        tool(
            &boundary,
            &mut processes[0],
            0,
            "vault.logout",
            AuthContext {
                auth_context: logins[0].auth_context.clone(),
            },
        )
        .await,
    );
    response(
        &boundary
            .action(&mut processes[0], 0, protected.clone())
            .await,
        403,
    );
    response(&boundary.action(&mut processes[1], 1, protected).await, 200);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 7);
    connections(&fixture, 9).await;
    assert!(
        fixture
            .origin
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.headers.contains_key("proxy-auth-context"))
    );
    observations(&boundary, 7, false).await;
    boundary.assert_no_bypass();
    for process in processes {
        process.finish().await;
    }
    stop(&mut daemon).await;
}
