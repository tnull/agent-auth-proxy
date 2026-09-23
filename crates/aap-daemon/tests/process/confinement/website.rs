use super::{boundary::Boundary, *};
use aap_types::{
    AuthContext, AuthState, GetLogin, Login, SearchItems, SearchResult, profile::LoginEncoding,
};

const PRIVATE: &[&str] = &[
    "private-website-user",
    "private-website-password",
    "private-website-cookie",
    "private-pre",
    "private-site-csrf",
];

pub(super) async fn tool(
    boundary: &Boundary,
    process: &mut Probe,
    session: usize,
    name: &str,
    arguments: impl serde::Serialize,
) -> Value {
    let value = boundary
        .action(
            process,
            session,
            json!({"kind":"mcp","name":name,"arguments":arguments}),
        )
        .await;
    let wire = serde_json::to_string(&value).unwrap();
    for private in PRIVATE {
        assert!(
            !wire.contains(private),
            "MCP result disclosed a private field"
        );
    }
    value["tool"].clone()
}
pub(super) fn success(result: Value) -> Value {
    assert_eq!(result["isError"], false, "MCP tool failed");
    result["structuredContent"].clone()
}
fn response(result: Value) -> Value {
    let response = success(result);
    assert_eq!(response["kind"], "response");
    assert_eq!(response["status"], 200);
    assert_eq!(response["complete"], true);
    for header in response["headers"].as_array().unwrap() {
        assert_ne!(header[0], "set-cookie");
    }
    let bytes = STANDARD
        .decode(response["body_base64"].as_str().unwrap())
        .unwrap();
    for private in PRIVATE {
        assert!(!String::from_utf8_lossy(&bytes).contains(private));
    }
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[ignore = "requires the explicit Linux confinement setup in docs/confinement.md"]
async fn confined_mcp_password_manager_keeps_form_and_json_sessions_private() {
    let _exclusive = LAUNCH_TEST_LOCK.lock().await;
    for encoding in [LoginEncoding::Form, LoginEncoding::Json] {
        website(encoding).await;
    }
}

async fn website(encoding: LoginEncoding) {
    let fixture = website_fixture_for(encoding).await;
    let (mut daemon, ready) = fixture.start().await;
    let boundary = Boundary::new(
        &fixture,
        &daemon,
        &ready,
        json!({"resources":["provider"],"items":["key"],"lifetime_seconds":120}),
        &[],
    )
    .await;
    let mut processes = [boundary.spawn(0).await, boundary.spawn(1).await];
    let uri = format!("{}/login", fixture.origin.origin());
    let found = success(
        tool(
            &boundary,
            &mut processes[0],
            0,
            "vault.search_items",
            SearchItems {
                uri: uri.clone(),
                query: None,
                cursor: None,
            },
        )
        .await,
    );
    let found: SearchResult = serde_json::from_value(found).unwrap();
    assert_eq!(found.items.len(), 1);
    assert_eq!(found.items[0].item_id, "key");
    let mut logins = vec![];
    for (index, process) in processes.iter_mut().enumerate() {
        let value = success(
            tool(
                &boundary,
                process,
                index,
                "vault.get_login",
                GetLogin {
                    request_id: aap_types::ids::random_id(16).unwrap(),
                    item_id: "key".into(),
                    uri: uri.clone(),
                },
            )
            .await,
        );
        let login: Login = serde_json::from_value(value).unwrap();
        assert!(matches!(
            login.credentials.username.kind,
            aap_types::CredentialKind::Placeholder
        ));
        assert!(matches!(
            login.credentials.password.kind,
            aap_types::CredentialKind::Placeholder
        ));
        logins.push(login);
    }
    assert_ne!(logins[0].auth_context, logins[1].auth_context);
    assert_ne!(
        logins[0].credentials.password.value,
        logins[1].credentials.password.value
    );
    let request = |context: &str, method: &str, path: &str, body: Vec<u8>| ExecuteRequest {
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
                if encoding == LoginEncoding::Form {
                    "application/x-www-form-urlencoded"
                } else {
                    "application/json"
                }
                .into(),
            )]
        },
        body_base64: STANDARD.encode(body),
    };
    let mut request_ids = vec![];
    for (index, process) in processes.iter_mut().enumerate() {
        let login = &logins[index];
        let page_request = request(&login.auth_context, "GET", "/login", vec![]);
        request_ids.push(page_request.request_id.clone());
        let page = response(tool(&boundary, process, index, "request.execute", page_request).await);
        assert_eq!(page["echo"], "[redacted]");
        let csrf = page["csrf"].as_str().unwrap();
        let body = if encoding == LoginEncoding::Form {
            format!(
                "user={}&password={}&csrf={csrf}",
                login.credentials.username.value, login.credentials.password.value
            )
            .into_bytes()
        } else {
            serde_json::to_vec(&json!({"user":login.credentials.username.value,"password":login.credentials.password.value,"csrf":csrf})).unwrap()
        };
        let login_request = request(&login.auth_context, "POST", "/session", body);
        request_ids.push(login_request.request_id.clone());
        let logged_in =
            response(tool(&boundary, process, index, "request.execute", login_request).await);
        assert_eq!(logged_in["authenticated"], true);
        assert_eq!(logged_in["echo"], "[redacted] [redacted]");
        let state = success(
            tool(
                &boundary,
                process,
                index,
                "vault.auth_status",
                AuthContext {
                    auth_context: login.auth_context.clone(),
                },
            )
            .await,
        );
        assert_eq!(state["state"], json!(AuthState::Authenticated));
        let protected = request(&login.auth_context, "GET", "/protected", vec![]);
        request_ids.push(protected.request_id.clone());
        assert_eq!(
            response(tool(&boundary, process, index, "request.execute", protected).await)["data"],
            "protected"
        );
        let crossed = request(&logins[1 - index].auth_context, "GET", "/protected", vec![]);
        assert_eq!(
            tool(&boundary, process, index, "request.execute", crossed).await["isError"],
            true
        );
    }
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 6);
    let logged_out = success(
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
    assert_eq!(logged_out["state"], json!(AuthState::Revoked));
    assert_eq!(
        tool(
            &boundary,
            &mut processes[0],
            0,
            "request.execute",
            request(&logins[0].auth_context, "GET", "/protected", vec![])
        )
        .await["isError"],
        true
    );
    let still_live = request(&logins[1].auth_context, "GET", "/protected", vec![]);
    request_ids.push(still_live.request_id.clone());
    assert_eq!(
        response(
            tool(
                &boundary,
                &mut processes[1],
                1,
                "request.execute",
                still_live
            )
            .await
        )["data"],
        "protected"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 7);
    let collector = boundary.tiny_collector(1).await;
    let denied = tool(
        &boundary,
        &mut processes[1],
        1,
        "request.execute",
        request(&logins[1].auth_context, "GET", "/protected", vec![]),
    )
    .await;
    assert_eq!(denied["isError"], true);
    assert_eq!(
        denied["structuredContent"]["code"],
        json!(ErrorCode::ObservationUnavailable)
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 7);
    boundary.remove_collector(collector).await;
    let resumed = request(&logins[1].auth_context, "GET", "/protected", vec![]);
    request_ids.push(resumed.request_id.clone());
    assert_eq!(
        response(tool(&boundary, &mut processes[1], 1, "request.execute", resumed).await)["data"],
        "protected"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 8);
    let mut approval = boundary.approval_process(&fixture, &["provider"]).await;
    let login = success(
        tool(
            &boundary,
            &mut approval,
            0,
            "vault.get_login",
            GetLogin {
                request_id: aap_types::ids::random_id(16).unwrap(),
                item_id: "key".into(),
                uri,
            },
        )
        .await,
    );
    let denied = tool(
        &boundary,
        &mut approval,
        0,
        "request.execute",
        request(
            login["auth_context"].as_str().unwrap(),
            "GET",
            "/login",
            vec![],
        ),
    )
    .await;
    assert_eq!(denied["isError"], true);
    assert_eq!(
        denied["structuredContent"]["code"],
        json!(ErrorCode::InteractionUnavailable)
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 8);
    approval.finish().await;
    for process in processes {
        process.finish().await;
    }
    let (records, gaps) = boundary.observations().await;
    assert!(
        !gaps.is_empty(),
        "recording rejection must remain visible to the observer"
    );
    for id in request_ids {
        assert_eq!(
            records
                .iter()
                .filter(|record| record.event.request_id.as_deref() == Some(&id)
                    && matches!(
                        record.event.data,
                        aap_observe::Data::FlowClose { complete: true, .. }
                    ))
                .count(),
            2
        );
    }
    for record in records {
        if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
            let bytes = STANDARD.decode(body_base64).unwrap();
            let content = String::from_utf8_lossy(&bytes);
            for private in PRIVATE
                .iter()
                .copied()
                .chain(["aap_pw1_", "aap_un1_", "aap_cs1_"])
            {
                assert!(!content.contains(private));
            }
        }
    }
    boundary.assert_no_bypass();
    stop(&mut daemon).await;
}
