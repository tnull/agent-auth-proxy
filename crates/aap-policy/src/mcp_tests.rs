use crate::*;
use serde_json::{Value, json};

fn enrolled() -> Value {
    json!({
        "id":"remote-tools", "origin":"https://tools.example",
        "addresses":{"mode":"public"},
        "routes":[{
            "method":"POST", "path":"/mcp", "query":null,
            "max_request_bytes":262144, "max_response_bytes":1048576,
            "allowed_headers":["content-type","accept","mcp-protocol-version"]
        },{
            "method":"DELETE", "path":"/mcp", "query":null,
            "max_request_bytes":1, "max_response_bytes":1024,
            "allowed_headers":[]
        }],
        "auth":{"kind":"mcp","item_id":"tool-key","header":"authorization",
            "prefix":"Bearer ","tools":[{
                "name":"echo","description":"Return supplied text",
                "arguments":{"text":{"kind":"text","max_length":1024}}
            }]}
    })
}
fn profile(value: Value) -> ResourceProfile {
    serde_json::from_value(value).expect("the enrolled MCP profile is supported")
}
fn catalog() -> Catalog {
    serde_json::from_value(json!({
        "schema_version":1,"configuration_revision":1,
        "items":[{"item_id":"tool-key","label":"Tools","account_alias":"work",
            "profile":"remote-tools","credential":{"store":"default","key":"native-key"}}]
    }))
    .unwrap()
}

#[test]
fn remote_mcp_enrollment_binds_an_exact_endpoint_and_credential() {
    let p = profile(enrolled());
    assert!(p.validate().is_ok());
    assert!(
        catalog()
            .validate(std::slice::from_ref(&p), &["default"], 1)
            .is_ok()
    );
    let target = Target::parse("https://tools.example/mcp").unwrap();
    assert!(p.authorize("POST", &target, 262144).is_ok());
    assert!(p.authorize("DELETE", &target, 0).is_ok());
    assert!(p.authorize("GET", &target, 0).is_err());
    assert!(p.authorize("POST", &target, 262145).is_err());
    for target in [
        "https://other.example/mcp",
        "https://tools.example/other",
        "https://tools.example/mcp?account=other",
    ] {
        assert!(
            p.authorize("POST", &Target::parse(target).unwrap(), 1)
                .is_err()
        );
    }
    let mut missing = catalog();
    missing.items.clear();
    assert!(
        missing
            .validate(std::slice::from_ref(&p), &["default"], 1)
            .is_err()
    );
    let mut wrong = catalog();
    wrong.items[0].item_id = "other-key".into();
    assert!(wrong.validate(&[p], &["default"], 1).is_err());
}

#[test]
fn private_mcp_transport_headers_cannot_be_enrolled_as_caller_fields() {
    for name in ["mcp-session-id", "last-event-id"] {
        let mut value = enrolled();
        value["auth"] = json!({"kind":"none"});
        value["routes"][0]["allowed_headers"] = json!([name]);
        let p = profile(value);
        assert!(p.validate().is_err(), "private MCP header admitted: {name}");
        assert!(
            p.routes[0]
                .authorize_headers(&[(name.to_uppercase(), "forged".into())])
                .is_err()
        );
    }
}

#[test]
fn remote_mcp_enrollment_rejects_route_and_header_escape_hatches() {
    let baseline = enrolled();
    assert!(profile(baseline.clone()).validate().is_ok());
    for (pointer, replacement) in [
        ("/routes/0/method", json!("GET")),
        ("/routes/1/path", json!("/cleanup")),
        ("/routes/0/query", json!("mode=raw")),
        ("/routes/0/streaming", json!(true)),
        ("/routes/0/max_request_bytes", json!(262145)),
        ("/routes/0/max_response_bytes", json!(1048577)),
        ("/routes/0/allowed_headers", json!(["x-client-state"])),
        ("/auth/header", json!("content-type")),
        ("/auth/header", json!("accept")),
        ("/auth/header", json!("mcp-protocol-version")),
        ("/auth/header", json!("mcp-session-id")),
        ("/auth/header", json!("last-event-id")),
        ("/auth/prefix", json!("Bearer\r\nX-Escape: ")),
    ] {
        let mut candidate = baseline.clone();
        if pointer == "/routes/0/streaming" {
            candidate["routes"][0]["streaming"] = replacement;
        } else {
            *candidate.pointer_mut(pointer).unwrap() = replacement;
        }
        assert!(
            profile(candidate).validate().is_err(),
            "invalid MCP profile accepted: {pointer}"
        );
    }
}

#[test]
fn remote_mcp_enrollment_has_finite_reviewed_tool_contracts() {
    let baseline = enrolled();
    assert!(profile(baseline.clone()).validate().is_ok());
    let tool = baseline["auth"]["tools"][0].clone();
    for tools in [
        json!([]),
        json!([tool.clone(), tool.clone()]),
        json!(vec![tool; 33]),
    ] {
        let mut candidate = baseline.clone();
        candidate["auth"]["tools"] = tools;
        assert!(profile(candidate).validate().is_err());
    }
    for (field, value) in [
        ("name", json!("tool/escape")),
        ("description", json!("x".repeat(4097))),
        ("arguments", json!({"text":{"kind":"text","max_length":0}})),
        (
            "arguments",
            json!({"text":{"kind":"text","max_length":262145}}),
        ),
        (
            "arguments",
            json!({"n":{"kind":"integer","minimum":2,"maximum":1}}),
        ),
    ] {
        let mut candidate = baseline.clone();
        candidate["auth"]["tools"][0][field] = value;
        assert!(
            profile(candidate).validate().is_err(),
            "invalid tool field accepted: {field}"
        );
    }
}

#[test]
fn remote_mcp_catalog_cannot_share_an_endpoint_or_key_with_raw_profiles() {
    let p = profile(enrolled());
    let mut catalog = catalog();
    let mut raw = p.clone();
    raw.id = "raw".into();
    raw.auth = Authentication::None;
    assert!(
        catalog
            .validate(&[p.clone(), raw.clone()], &["default"], 1)
            .is_err()
    );
    for route in &mut raw.routes {
        route.path = "/other".into();
    }
    assert!(
        catalog
            .validate(&[p.clone(), raw.clone()], &["default"], 1)
            .is_ok()
    );
    raw.auth = Authentication::ApiKey {
        item_id: "raw-key".into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        provider: aap_types::profile::ProviderKind::Generic,
    };
    let mut item = catalog.items[0].clone();
    item.item_id = "raw-key".into();
    item.profile = "raw".into();
    catalog.items.push(item);
    assert!(
        catalog
            .validate(&[p.clone(), raw.clone()], &["default"], 1)
            .is_err()
    );
    catalog.items[1].credential.key = "other-native-key".into();
    assert!(catalog.validate(&[p.clone(), raw], &["default"], 1).is_ok());
    let mut value = enrolled();
    value["id"] = json!("second-account");
    value["auth"]["item_id"] = json!("second-key");
    let second = profile(value);
    catalog.items[1].profile = second.id.clone();
    catalog.items[1].item_id = "second-key".into();
    assert!(catalog.validate(&[p, second], &["default"], 1).is_ok());
}
