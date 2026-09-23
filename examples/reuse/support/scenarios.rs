//! Shared agent-side scenarios. No credentials, host configuration, or custody imports.
use aap_types::{
    AgentService, AuthContext, AuthState, CredentialKind, ErrorCode, ExecuteRequest, GetLogin,
    Login, OperationState, OperationStatus, Result, SearchItems,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Limited};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub completed: Vec<String>,
    pub uncertain: Vec<String>,
    pub authenticated_sessions: usize,
    pub protected_reads: usize,
    pub responses: Vec<ResponseView>,
    pub metadata: Vec<Value>,
    pub errors: Vec<aap_types::Error>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseView {
    /// Header values, like bodies, are base64 to preserve their exact bytes.
    pub headers: Vec<(String, String)>,
    pub body_base64: String,
    pub complete: bool,
}

fn id() -> String {
    aap_types::ids::random_id(16).expect("fixture ID generation failed")
}
fn request(
    origin: &str,
    resource: &str,
    context: Option<String>,
    method: &str,
    path: &str,
    body: Vec<u8>,
    content_type: &str,
) -> ExecuteRequest {
    ExecuteRequest {
        request_id: id(),
        resource: resource.into(),
        auth_context: context,
        method: method.into(),
        target: format!("{origin}{path}"),
        headers: if body.is_empty() {
            vec![]
        } else {
            vec![("content-type".into(), content_type.into())]
        },
        body_base64: STANDARD.encode(body),
    }
}
fn provider(origin: &str, text: &str) -> ExecuteRequest {
    request(
        origin,
        "provider",
        None,
        "POST",
        "/v1/chat/completions",
        serde_json::to_vec(
            &json!({"model":"fixture","messages":[{"role":"user","content":text}],"stream":true}),
        )
        .unwrap(),
        "application/json",
    )
}
fn website(origin: &str, login: &Login, method: &str, path: &str, body: Vec<u8>) -> ExecuteRequest {
    request(
        origin,
        "website",
        Some(login.auth_context.clone()),
        method,
        path,
        body,
        &login.submission.content_type,
    )
}
fn context(login: &Login) -> AuthContext {
    AuthContext {
        auth_context: login.auth_context.clone(),
    }
}
fn denied<T>(result: Result<T>, expected: ErrorCode, report: &mut Report) {
    match result {
        Err(error) => {
            assert_eq!(error.code, expected);
            report.errors.push(error);
        }
        Ok(_) => panic!("forbidden fixture operation was accepted"),
    }
}
async fn body(response: aap_types::Response, report: &mut Report) -> Result<Vec<u8>> {
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("set-cookie"));
    let mut view = ResponseView {
        headers: response
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), STANDARD.encode(value.as_bytes())))
            .collect(),
        body_base64: String::new(),
        complete: false,
    };
    let mut source = Limited::new(response.into_body(), 16 * 1024);
    let mut bytes = Vec::new();
    while let Some(frame) = source.frame().await {
        match frame {
            Ok(frame) => {
                bytes.extend_from_slice(&frame.into_data().expect("unexpected fixture trailers"))
            }
            Err(_) => {
                view.body_base64 = STANDARD.encode(&bytes);
                report.responses.push(view);
                return Err(ErrorCode::ResultUnavailable.into());
            }
        }
    }
    view.body_base64 = STANDARD.encode(&bytes);
    view.complete = true;
    report.responses.push(view);
    Ok(bytes)
}
async fn execute(
    service: &dyn AgentService,
    input: ExecuteRequest,
    report: &mut Report,
) -> Result<Vec<u8>> {
    let id = input.request_id.clone();
    let bytes = body(service.execute(input).await?, report).await?;
    assert_eq!(
        service.request_status(id.clone()).await?.state,
        OperationState::Completed
    );
    report.completed.push(id);
    Ok(bytes)
}
async fn existing(
    service: &dyn AgentService,
    input: ExecuteRequest,
    state: OperationState,
    report: &mut Report,
) -> Result<()> {
    let id = input.request_id.clone();
    let response = service.execute(input).await?;
    assert_eq!(response.headers()["x-aap-operation-state"], "existing");
    let value: OperationStatus = serde_json::from_slice(&body(response, report).await?).unwrap();
    assert_eq!(value.request_id, id);
    assert_eq!(value.state, state);
    Ok(())
}

pub async fn run(
    first: Arc<dyn AgentService>,
    second: Arc<dyn AgentService>,
    origin: &str,
) -> Result<Report> {
    let mut report = Report {
        completed: vec![],
        uncertain: vec![],
        authenticated_sessions: 0,
        protected_reads: 0,
        responses: vec![],
        metadata: vec![],
        errors: vec![],
    };
    let input = provider(origin, "hello");
    assert_eq!(
        execute(first.as_ref(), input.clone(), &mut report).await?,
        b"data: [redacted]\n\n"
    );
    existing(
        first.as_ref(),
        input.clone(),
        OperationState::Completed,
        &mut report,
    )
    .await?;
    assert_eq!(
        first.cancel(input.request_id.clone()).await?.state,
        OperationState::Completed
    );
    let mut changed = provider(origin, "lost");
    changed.request_id = input.request_id;
    denied(
        first.execute(changed).await,
        ErrorCode::RequestConflict,
        &mut report,
    );
    let mut forbidden = provider(origin, "hello");
    forbidden.resource = "not-granted".into();
    denied(
        first.execute(forbidden).await,
        ErrorCode::PolicyDenied,
        &mut report,
    );
    denied(
        first
            .execute(provider("https://not-enrolled.invalid", "hello"))
            .await,
        ErrorCode::PolicyDenied,
        &mut report,
    );

    let uri = format!("{origin}/login");
    let found = first
        .search_items(SearchItems {
            uri: uri.clone(),
            query: None,
            cursor: None,
        })
        .await?;
    assert_eq!(found.items.len(), 1);
    assert_eq!(found.items[0].item_id, "account");
    report.metadata.push(serde_json::to_value(&found).unwrap());
    let mut logins = vec![];
    for service in [&first, &second] {
        let issuance = GetLogin {
            request_id: id(),
            item_id: "account".into(),
            uri: uri.clone(),
        };
        let login = service.get_login(issuance.clone()).await?;
        let again = service.get_login(issuance).await?;
        report.metadata.push(serde_json::to_value(&login).unwrap());
        report.metadata.push(serde_json::to_value(&again).unwrap());
        assert_eq!(login.auth_context, again.auth_context);
        assert_eq!(
            login.credentials.password.value,
            again.credentials.password.value
        );
        assert!(matches!(
            login.credentials.username.kind,
            CredentialKind::Placeholder
        ));
        assert!(matches!(
            login.credentials.password.kind,
            CredentialKind::Placeholder
        ));
        assert!(login.credentials.username.value.starts_with("aap_un1_"));
        assert!(login.credentials.password.value.starts_with("aap_pw1_"));
        let bytes = execute(
            service.as_ref(),
            website(origin, &login, "GET", "/login", vec![]),
            &mut report,
        )
        .await?;
        let page: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(page["echo"], "[redacted]");
        let csrf = page["csrf"].as_str().unwrap();
        assert!(csrf.starts_with("aap_cs1_"));
        let submitted=match login.submission.content_type.as_str() {
            "application/x-www-form-urlencoded"=>format!("user={}&password={}&csrf={csrf}",login.credentials.username.value,login.credentials.password.value).into_bytes(),
            "application/json"=>serde_json::to_vec(&json!({"user":login.credentials.username.value,"password":login.credentials.password.value,"csrf":csrf})).unwrap(),
            _=>panic!("unsupported fixture encoding"),
        };
        let bytes = execute(
            service.as_ref(),
            website(origin, &login, "POST", "/session", submitted),
            &mut report,
        )
        .await?;
        let logged: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(logged["authenticated"], true);
        assert_eq!(logged["echo"], "[redacted] [redacted] [redacted]");
        assert_eq!(
            service.auth_status(context(&login)).await?.state,
            AuthState::Authenticated
        );
        report.authenticated_sessions += 1;
        let bytes = execute(
            service.as_ref(),
            website(origin, &login, "GET", "/protected", vec![]),
            &mut report,
        )
        .await?;
        let protected: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(protected["data"], "protected");
        assert_eq!(protected["echo"], "[redacted]");
        report.protected_reads += 1;
        logins.push(login);
    }
    assert_ne!(logins[0].auth_context, logins[1].auth_context);
    assert_ne!(
        logins[0].credentials.password.value,
        logins[1].credentials.password.value
    );
    denied(
        first
            .execute(website(origin, &logins[1], "GET", "/protected", vec![]))
            .await,
        ErrorCode::PolicyDenied,
        &mut report,
    );
    denied(
        second
            .execute(website(origin, &logins[0], "GET", "/protected", vec![]))
            .await,
        ErrorCode::PolicyDenied,
        &mut report,
    );
    assert_eq!(
        first.logout(context(&logins[0])).await?.state,
        AuthState::Revoked
    );
    denied(
        first
            .execute(website(origin, &logins[0], "GET", "/protected", vec![]))
            .await,
        ErrorCode::PlaceholderInvalid,
        &mut report,
    );
    let bytes = execute(
        second.as_ref(),
        website(origin, &logins[1], "GET", "/protected", vec![]),
        &mut report,
    )
    .await?;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["data"],
        "protected"
    );
    report.protected_reads += 1;
    assert_eq!(
        second.logout(context(&logins[1])).await?.state,
        AuthState::Revoked
    );

    let input = provider(origin, "cancel");
    let cancel_id = input.request_id.clone();
    let response = first.execute(input.clone()).await?;
    assert_eq!(
        first.request_status(cancel_id.clone()).await?.state,
        OperationState::Dispatching
    );
    assert_eq!(
        first.cancel(cancel_id.clone()).await?.state,
        OperationState::OutcomeUnknown
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(3), body(response, &mut report))
            .await
            .expect("cancellation did not terminate delivery")
            .is_err()
    );
    existing(
        first.as_ref(),
        input,
        OperationState::OutcomeUnknown,
        &mut report,
    )
    .await?;
    report.uncertain.push(cancel_id);
    let lost = provider(origin, "lost");
    let lost_id = lost.request_id.clone();
    denied(
        first.execute(lost.clone()).await,
        ErrorCode::OutcomeUnknown,
        &mut report,
    );
    assert_eq!(
        first.request_status(lost_id.clone()).await?.state,
        OperationState::OutcomeUnknown
    );
    existing(
        first.as_ref(),
        lost,
        OperationState::OutcomeUnknown,
        &mut report,
    )
    .await?;
    report.uncertain.push(lost_id);
    Ok(report)
}
