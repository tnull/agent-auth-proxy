use super::{Info, Result, origin, wire::Mcp};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

fn id() -> Result<String> {
    aap_types::ids::random_id(16).map_err(|_| "randomness unavailable".into())
}
fn request(
    info: &Info,
    resource: &str,
    context: Option<&str>,
    method: &str,
    path: &str,
    body: String,
) -> Result<Value> {
    Ok(
        json!({"request_id":id()?,"resource":resource,"auth_context":context,"method":method,
        "target":format!("{}{path}",info.origin),
        "headers":if body.is_empty() {vec![]} else {vec![("content-type", if resource == "provider" {"application/json"} else {"application/x-www-form-urlencoded"})]},
        "body_base64":STANDARD.encode(body)}),
    )
}
async fn response(peer: &mut Mcp, args: Value) -> Result<Value> {
    let value = peer.success("request.execute", args).await?;
    if value["kind"] != "response" || value["status"] != 200 || value["complete"] != true {
        return Err("demo HTTP response was not complete and successful".into());
    }
    if value["headers"]
        .as_array()
        .ok_or("missing HTTP headers")?
        .iter()
        .any(|header| header[0] == "set-cookie")
    {
        return Err("private cookie header escaped".into());
    }
    let bytes = STANDARD.decode(value["body_base64"].as_str().ok_or("missing HTTP body")?)?;
    origin::clean(&bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn run(info: &Info) -> Result<Value> {
    let mut peer = Mcp::start(&info.daemon, &info.session_socket).await?;
    let provider = response(
        &mut peer,
        request(
            info,
            "provider",
            None,
            "POST",
            "/v1/chat/completions",
            json!({"model":"demo","messages":[{"role":"user","content":"hello"}],"stream":false})
                .to_string(),
        )?,
    )
    .await?;
    if provider["credential_echo"] != "[redacted]" {
        return Err("provider injection/redaction failed".into());
    }
    let uri = format!("{}/login", info.origin);
    let search = peer
        .success("vault.search_items", json!({"uri":uri}))
        .await?;
    if search["items"][0]["item_id"] != "account" {
        return Err("demo credential discovery failed".into());
    }
    let login = peer
        .success(
            "vault.get_login",
            json!({"request_id":id()?,"item_id":"account","uri":uri}),
        )
        .await?;
    let login: aap_types::Login = serde_json::from_value(login)?;
    if !matches!(
        login.credentials.username.kind,
        aap_types::CredentialKind::Placeholder
    ) || !matches!(
        login.credentials.password.kind,
        aap_types::CredentialKind::Placeholder
    ) {
        return Err("demo did not receive placeholder credentials".into());
    }
    let context = Some(login.auth_context.as_str());
    let page = response(
        &mut peer,
        request(info, "website", context, "GET", "/login", String::new())?,
    )
    .await?;
    let csrf = page["csrf"].as_str().ok_or("missing CSRF placeholder")?;
    if !csrf.starts_with("aap_cs1_") {
        return Err("CSRF was not virtualized".into());
    }
    let body = format!(
        "user={}&password={}&csrf={csrf}",
        login.credentials.username.value, login.credentials.password.value
    );
    let logged_in = response(
        &mut peer,
        request(info, "website", context, "POST", "/session", body)?,
    )
    .await?;
    if logged_in["authenticated"] != true {
        return Err("demo login failed".into());
    }
    let protected = response(
        &mut peer,
        request(info, "website", context, "GET", "/protected", String::new())?,
    )
    .await?;
    if protected["data"] != "demo protected resource" || protected["cookie_echo"] != "[redacted]" {
        return Err("private-cookie resource access failed".into());
    }
    let status = peer
        .success(
            "vault.auth_status",
            json!({"auth_context":login.auth_context}),
        )
        .await?;
    if status["state"] != "authenticated" {
        return Err("unexpected login state".into());
    }
    peer.success("vault.logout", json!({"auth_context":login.auth_context}))
        .await?;
    let denied = peer
        .tool(
            "request.execute",
            request(info, "website", context, "GET", "/protected", String::new())?,
        )
        .await?;
    if denied["isError"] != true || denied["structuredContent"]["code"] != "placeholder_invalid" {
        return Err("logged-out context was accepted".into());
    }
    peer.close().await?;
    Ok(json!({
        "demo":"passed", "provider_key_injected":true, "website_authenticated":true,
        "provider_reply":provider["choices"][0]["message"]["content"],
        "password_placeholder":login.credentials.password.value,
        "protected_data":protected["data"], "logout_denied_reuse":true,
        "credential_echoes":"[redacted]", "transport":"real stdio MCP -> daemon -> verified local HTTPS",
    }))
}
