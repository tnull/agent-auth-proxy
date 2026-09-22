use rmcp::model::Tool;
use serde_json::{Value, json};

pub const NAMES: [&str; 7] = [
    "vault.search_items",
    "vault.get_login",
    "vault.auth_status",
    "vault.logout",
    "request.execute",
    "request.status",
    "request.cancel",
];

pub fn definitions() -> Vec<Tool> {
    let string = || json!({"type":"string"});
    let request_id = || json!({"type":"string","pattern":"^[A-Za-z0-9_-]{22}$"});
    let context = || json!({"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"});
    let nullable = || json!({"type":["string","null"]});
    vec![
        tool(
            NAMES[0],
            "Search only permitted enrolled login items for an exact site.",
            json!({"uri":string(),"query":nullable(),"cursor":nullable()}),
            &["uri"],
        ),
        tool(
            NAMES[1],
            "Prepare fake login values. Real passwords remain inside the broker.",
            json!({"request_id":request_id(),"item_id":string(),"uri":string()}),
            &["request_id", "item_id", "uri"],
        ),
        tool(
            NAMES[2],
            "Inspect this session's authentication context without revealing cookies.",
            json!({"auth_context":context()}),
            &["auth_context"],
        ),
        tool(
            NAMES[3],
            "Revoke this authentication context and its private local cookie jar.",
            json!({"auth_context":context()}),
            &["auth_context"],
        ),
        tool(
            NAMES[4],
            "Execute one bounded, policy-admitted HTTPS operation. Never blindly repeat uncertain work under a new ID.",
            json!({
                "request_id":request_id(),"resource":string(),"auth_context":nullable(),"method":string(),"target":string(),
                "headers":{"type":"array","maxItems":64,"items":{"type":"array","prefixItems":[string(),string()],"minItems":2,"maxItems":2}},
                "body_base64":{"type":"string","description":"Canonical padded standard base64 of exact request bytes; empty means no body."}
            }),
            &["request_id", "resource", "method", "target"],
        ),
        tool(
            NAMES[5],
            "Inspect an existing operation without dispatching it again.",
            json!({"request_id":request_id()}),
            &["request_id"],
        ),
        tool(
            NAMES[6],
            "Cancel an operation where possible. Remote execution is not rolled back.",
            json!({"request_id":request_id()}),
            &["request_id"],
        ),
    ]
}
fn tool(
    name: &'static str,
    description: &'static str,
    properties: Value,
    required: &[&str],
) -> Tool {
    let schema = json!({"type":"object","properties":properties,"required":required,"additionalProperties":false});
    Tool::new(
        name,
        description,
        schema
            .as_object()
            .expect("literal schema is an object")
            .clone(),
    )
}
