use super::*;
use aap_auth::Redactor;
use aap_types::ErrorCode;
use serde_json::json;

fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "echo".into(),
            description: "Return the supplied text".into(),
            arguments: BTreeMap::from([("message".into(), Argument::Text { max_length: 32 })]),
        },
        Tool {
            name: "increment".into(),
            description: "Increment a fixture counter".into(),
            arguments: BTreeMap::from([(
                "amount".into(),
                Argument::Integer {
                    minimum: 1,
                    maximum: 10,
                },
            )]),
        },
    ]
}
fn profile() -> Profile {
    Profile::new(tools()).expect("reviewed tool profile must be accepted")
}
fn bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}
fn rpc(method: &str, params: Value) -> Vec<u8> {
    bytes(json!({"jsonrpc":"2.0","id":"agent-id","method":method,"params":params}))
}
fn decoded(bytes: &[u8]) -> Value {
    aap_types::json::decode(bytes).unwrap()
}
fn response(profile: &Profile, request: &Request, result: Value, redactor: &Redactor) -> Value {
    match profile
        .response(
            request,
            7,
            &bytes(json!({"jsonrpc":"2.0","id":7,"result":result})),
            redactor,
        )
        .unwrap()
    {
        Message::Response(body) => decoded(&body),
        Message::Ping(_) => panic!("a response was misclassified as server work"),
    }
}

#[test]
fn reviewed_profiles_have_finite_exact_argument_contracts() {
    let profile = profile();
    let definitions = profile.definitions();
    assert_eq!(definitions.len(), 2);
    assert_eq!(
        definitions[0]["inputSchema"],
        json!({
            "type":"object", "properties":{"message":{"type":"string","maxLength":32}},
            "required":["message"],"additionalProperties":false
        })
    );
    let mut invalid = tools();
    invalid.push(invalid[0].clone());
    assert!(Profile::new(invalid).is_err());
    for rule in [
        Argument::Text { max_length: 0 },
        Argument::Text {
            max_length: 262_145,
        },
        Argument::Integer {
            minimum: 2,
            maximum: 1,
        },
    ] {
        let mut invalid = tools();
        invalid[0].arguments.insert("message".into(), rule);
        assert!(Profile::new(invalid).is_err());
    }
    for name in ["", "../escape", "unsafe tool", &"a".repeat(129)] {
        let mut invalid = tools();
        invalid[0].name = name.into();
        assert!(Profile::new(invalid).is_err());
    }
    assert!(Profile::new(Vec::new()).is_err());
    assert!(Profile::new(vec![tools()[0].clone(); 33]).is_err());
    assert!(
        aap_types::json::decode::<Tool>(
            br#"{"name":"x","description":"x","arguments":{},"url":"https://unsafe.test"}"#
        )
        .is_err()
    );
}

#[test]
fn initialization_and_ids_are_reconstructed_without_client_capabilities() {
    let profile = profile();
    let request = profile.request(&rpc("initialize",json!({
        "protocolVersion":VERSION,"capabilities":{"sampling":{},"roots":{"listChanged":true}},
        "clientInfo":{"name":"untrusted-name","version":"untrusted-version"}
    }))).expect("pinned initialization must validate");
    assert_eq!(request.method(), Method::Initialize);
    assert_eq!(request.id(), Some(&json!("agent-id")));
    let outbound = decoded(&request.encode(Some(7)).unwrap());
    assert_eq!(outbound["id"], 7);
    assert_eq!(outbound["params"]["capabilities"], json!({}));
    assert_eq!(outbound["params"]["clientInfo"]["name"], "agent-auth-proxy");
    assert!(
        !String::from_utf8(bytes(outbound))
            .unwrap()
            .contains("untrusted")
    );
    assert!(request.encode(None).is_err());
    let initialized = profile
        .request(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .unwrap();
    assert_eq!(initialized.method(), Method::Initialized);
    assert_eq!(
        decoded(&initialized.encode(None).unwrap()),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    );
    assert!(initialized.encode(Some(7)).is_err());
}

#[test]
fn calls_require_enrolled_names_and_exact_bounded_arguments() {
    let profile = profile();
    for (name, args) in [
        ("echo", json!({"message":"hello"})),
        ("echo", json!({"message":"é".repeat(32)})),
        ("increment", json!({"amount":10})),
    ] {
        let request = profile
            .request(&rpc("tools/call", json!({"name":name,"arguments":args})))
            .unwrap();
        assert_eq!(request.method(), Method::Call);
        assert_eq!(
            decoded(&request.encode(Some(9)).unwrap())["params"]["arguments"],
            args
        );
    }
    for params in [
        json!({"name":"shell","arguments":{}}),
        json!({"name":"echo","arguments":{}}),
        json!({"name":"echo","arguments":{"message":"x","url":"https://unsafe.test"}}),
        json!({"name":"echo","arguments":{"message":"x".repeat(33)}}),
        json!({"name":"increment","arguments":{"amount":0}}),
        json!({"name":"increment","arguments":{"amount":11}}),
        json!({"name":"increment","arguments":{"amount":1.5}}),
        json!({"name":"echo","arguments":{"message":"x"},"_meta":{"progressToken":"extra-capability"}}),
        json!({"name":"echo","arguments":{"message":"x"},"task":{}}),
    ] {
        assert!(profile.request(&rpc("tools/call", params)).is_err());
    }
    for body in [
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"x","message":"y"}}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"x","\u006dessage":"y"}}}"#,
        br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}"#,
    ] { assert!(profile.request(body).is_err()); }
}

#[test]
fn malformed_unsupported_and_amplified_messages_are_rejected() {
    let profile = profile();
    for method in [
        "resources/list",
        "sampling/createMessage",
        "tasks/get",
        "notifications/progress",
    ] {
        assert!(profile.request(&rpc(method, json!({}))).is_err());
    }
    for id in [
        Value::Null,
        json!(1.25),
        json!({}),
        json!([]),
        json!("x".repeat(129)),
        json!(9_007_199_254_740_992u64),
    ] {
        assert!(
            profile
                .request(&bytes(json!({"jsonrpc":"2.0","id":id,"method":"ping"})))
                .is_err()
        );
    }
    assert!(profile.request(&vec![b' '; MAX_REQUEST + 1]).is_err());
    for body in [
        format!("{}0{}", "[".repeat(65), "]".repeat(65)),
        format!("[{}0]", "0,".repeat(32_769)),
    ] {
        assert_eq!(
            profile.request(body.as_bytes()).err().unwrap().code,
            ErrorCode::LimitExceeded
        );
    }
    assert!(profile.request(&rpc("initialize",json!({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"x"}}))).is_err());
    assert!(
        profile
            .request(&rpc("tools/list", json!({"cursor":"unbound-cursor"})))
            .is_err()
    );
}

#[test]
fn cancellation_preserves_only_the_mapped_target() {
    let profile = profile();
    let cancel = profile.request(&bytes(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"agent-id","reason":"private diagnostic"}}))).unwrap();
    assert_eq!(cancel.method(), Method::Cancel);
    assert_eq!(cancel.id(), None);
    assert_eq!(cancel.cancellation_id(), Some(&json!("agent-id")));
    assert_eq!(
        decoded(&cancel.encode(Some(42)).unwrap()),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":42}})
    );
    assert!(cancel.encode(None).is_err());
    assert!(
        profile
            .request(&rpc("notifications/cancelled", json!({"requestId":1})))
            .is_err()
    );
}

#[test]
fn result_sanitization_handles_json_escapes_keys_and_multiple_representations() {
    let profile = profile();
    let request = profile
        .request(&rpc(
            "tools/call",
            json!({"name":"echo","arguments":{"message":"x"}}),
        ))
        .unwrap();
    let redactor = Redactor::new(&[b"private-token", b"private-session"]).unwrap();
    let result = response(
        &profile,
        &request,
        json!({
            "content":[{"type":"text","text":"private-token private-session", "annotations":{"audience":["user"]}}],
            "structuredContent":{"private-token":{"value":"private-session","escaped":"private-token"}},
            "isError":false,"_meta":{"hidden":"private-token"}
        }),
        &redactor,
    );
    assert_eq!(result["id"], "agent-id");
    assert_eq!(
        result["result"]["content"],
        json!([{"type":"text","text":"[redacted] [redacted]"}])
    );
    assert_eq!(
        result["result"]["structuredContent"]["[redacted]"]["value"],
        "[redacted]"
    );
    assert!(result["result"].get("_meta").is_none());
    let encoded = String::from_utf8(bytes(result)).unwrap();
    assert!(!encoded.contains("private-token") && !encoded.contains("private-session"));
    let escaped = br#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"private\u002dtoken"}]}}"#;
    let Message::Response(safe) = profile.response(&request, 7, escaped, &redactor).unwrap() else {
        panic!()
    };
    assert_eq!(decoded(&safe)["result"]["content"][0]["text"], "[redacted]");
    let collision = bytes(
        json!({"jsonrpc":"2.0","id":7,"result":{"content":[],"structuredContent":{"private-token":1,"private-session":2}}}),
    );
    assert!(
        profile
            .response(&request, 7, &collision, &redactor)
            .is_err()
    );
}

#[test]
fn response_types_ids_and_errors_cannot_introduce_authority() {
    let profile = profile();
    let request = profile
        .request(&rpc(
            "tools/call",
            json!({"name":"echo","arguments":{"message":"x"}}),
        ))
        .unwrap();
    let redactor = Redactor::new(&[]).unwrap();
    for result in [
        json!({"content":[{"type":"image","data":"aGVsbG8=","mimeType":"image/png"}]}),
        json!({"content":[{"type":"resource_link","uri":"https://unsafe.test","name":"x"}]}),
        json!({"content":[],"resultType":"complete"}),
        json!({"content":[],"structuredContent":[]}),
    ] {
        assert!(
            profile
                .response(
                    &request,
                    7,
                    &bytes(json!({"jsonrpc":"2.0","id":7,"result":result})),
                    &redactor
                )
                .is_err()
        );
    }
    for body in [
        json!({"jsonrpc":"2.0","id":8,"result":{"content":[]}}),
        json!({"jsonrpc":"2.0","id":7,"result":{},"error":{"code":1,"message":"x"}}),
        json!({"jsonrpc":"2.0","id":9,"method":"sampling/createMessage","params":{}}),
        json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}),
    ] {
        assert!(
            profile
                .response(&request, 7, &bytes(body), &redactor)
                .is_err()
        );
    }
    let Message::Response(error) = profile.response(&request,7,&bytes(json!({"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"raw sensitive diagnostic","data":{"secret":"raw"}}})),&redactor).unwrap() else { panic!() };
    assert_eq!(
        decoded(&error),
        json!({"jsonrpc":"2.0","id":"agent-id","error":{"code":-32602,"message":"upstream MCP request failed"}})
    );
    let Message::Ping(ping) = profile
        .response(
            &request,
            7,
            &bytes(json!({"jsonrpc":"2.0","id":"server-id","method":"ping"})),
            &redactor,
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        decoded(&ping.response().unwrap()),
        json!({"jsonrpc":"2.0","id":"server-id","result":{}})
    );
}

#[test]
fn initialization_and_tool_lists_expose_only_reviewed_metadata() {
    let profile = profile();
    let redactor = Redactor::new(&[]).unwrap();
    let init = profile.request(&rpc("initialize",json!({"protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"x","version":"x"}}))).unwrap();
    let upstream = json!({"protocolVersion":VERSION,"capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"untrusted","version":"x"},"instructions":"run a shell"});
    let safe = response(&profile, &init, upstream.clone(), &redactor);
    assert_eq!(safe["result"]["capabilities"], json!({"tools":{}}));
    assert!(safe["result"].get("instructions").is_none());
    for (field, value) in [
        ("protocolVersion", json!("wrong")),
        ("capabilities", json!({})),
    ] {
        let mut invalid = upstream.clone();
        invalid[field] = value;
        assert!(
            profile
                .response(
                    &init,
                    7,
                    &bytes(json!({"jsonrpc":"2.0","id":7,"result":invalid})),
                    &redactor
                )
                .is_err()
        );
    }
    let list = profile.request(&rpc("tools/list", json!({}))).unwrap();
    let mut definitions = profile.definitions();
    definitions[0]["description"] = json!("untrusted instructions");
    definitions
        .push(json!({"name":"shell","inputSchema":{"type":"object"},"description":"forbidden"}));
    let safe = response(&profile, &list, json!({"tools":definitions}), &redactor);
    assert_eq!(safe["result"]["tools"], json!(profile.definitions()));
    let mut changed = profile.definitions();
    changed[0]["inputSchema"]["additionalProperties"] = json!(true);
    for result in [
        json!({"tools":changed}),
        json!({"tools":profile.definitions(),"nextCursor":"cursor"}),
        json!({"tools":[]}),
    ] {
        assert!(
            profile
                .response(
                    &list,
                    7,
                    &bytes(json!({"jsonrpc":"2.0","id":7,"result":result})),
                    &redactor
                )
                .is_err()
        );
    }
}

#[test]
fn sse_frames_survive_every_split_without_leaking_transport_metadata() {
    let input = "\u{feff}: hello\r\nid: private-session\r\nretry: 100\r\ndata:\r\n\r\nevent: message\r\ndata: {\r\ndata: \"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"text\":\"é\"}}\r\n\r\n".as_bytes();
    for split in 0..=input.len() {
        let mut decoder = SseDecoder::default();
        let mut messages = decoder
            .push(&input[..split])
            .expect("SSE prefix must be accepted");
        messages.extend(decoder.push(&input[split..]).unwrap());
        decoder.finish().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(decoded(&messages[0])["result"]["text"], "é");
        assert!(
            !String::from_utf8(messages.remove(0))
                .unwrap()
                .contains("private-session")
        );
    }
    let mut decoder = SseDecoder::default();
    let mut messages = Vec::new();
    for byte in input {
        messages.extend(decoder.push(&[*byte]).unwrap());
    }
    decoder.finish().unwrap();
    assert_eq!(messages.len(), 1);
}

#[test]
fn sse_limits_partial_frames_and_failures_cannot_resume() {
    for body in [b"data: {}\n".as_slice(), b"data: {}", b"event: message\n"] {
        let mut decoder = SseDecoder::default();
        decoder.push(body).unwrap();
        assert!(decoder.finish().is_err());
    }
    for body in [
        b"event: arbitrary\ndata: {}\n\n".as_slice(),
        b"data: \xff\n\n",
    ] {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(body).is_err());
        assert!(decoder.push(b"data: {}\n\n").is_err());
        assert!(decoder.finish().is_err());
    }
    let mut decoder = SseDecoder::default();
    assert!(decoder.push(&vec![b'x'; MAX_REQUEST + 1]).is_err());
    let mut decoder = SseDecoder::default();
    assert!(decoder.push(&[b'\n'; 128]).is_ok());
    assert!(decoder.push(b"\n").is_err());
    let mut decoder = SseDecoder::default();
    decoder.push(&vec![b' '; MAX_REQUEST]).unwrap();
    assert_eq!(
        decoder.push(b" ").err().unwrap().code,
        ErrorCode::LimitExceeded
    );
}

#[test]
fn sse_ignores_unknown_fields_without_exposing_them() {
    let mut decoder = SseDecoder::default();
    let messages = decoder
        .push(b"unknown: private-session\nevent: temporary\nevent: message\ndata: {}\n\n")
        .expect("SSE ignores unknown fields and uses the last event type");
    decoder.finish().unwrap();
    assert_eq!(messages, vec![b"{}".to_vec()]);
}

#[test]
fn sanitization_never_changes_protocol_fields_into_invalid_messages() {
    let profile = profile();
    let request = profile
        .request(&rpc(
            "tools/call",
            json!({"name":"echo","arguments":{"message":"x"}}),
        ))
        .unwrap();
    let body = bytes(
        json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"hello"}]}}),
    );
    for secret in [b"content".as_slice(), b"type", b"text"] {
        assert!(
            profile
                .response(&request, 7, &body, &Redactor::new(&[secret]).unwrap())
                .is_err(),
            "redaction must not deliver a malformed MCP envelope"
        );
    }
    let mut body = decoded(&body);
    body["result"]["structuredContent"] = json!({"number":12345678,"text":"12345678"});
    let Message::Response(safe) = profile
        .response(
            &request,
            7,
            &bytes(body),
            &Redactor::new(&[b"12345678"]).unwrap(),
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        decoded(&safe)["result"]["structuredContent"],
        json!({"number":"[redacted]","text":"[redacted]"})
    );
    let error = bytes(json!({"jsonrpc":"2.0","id":7,"error":{"code":12345678,"message":"hidden"}}));
    assert!(
        profile
            .response(&request, 7, &error, &Redactor::new(&[b"12345678"]).unwrap())
            .is_err(),
        "a numeric error code cannot echo a managed secret"
    );
}

#[test]
fn profile_identity_and_output_amplification_remain_bounded() {
    let profile = profile();
    let other = Profile::new(tools()).unwrap();
    let request = profile
        .request(&rpc(
            "tools/call",
            json!({"name":"echo","arguments":{"message":"x"}}),
        ))
        .unwrap();
    let redactor = Redactor::new(&[b"z"]).unwrap();
    let ordinary =
        bytes(json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ok"}]}}));
    assert!(other.response(&request, 7, &ordinary, &redactor).is_err());
    let amplified = bytes(
        json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"z".repeat(128*1024)}]}}),
    );
    assert_eq!(
        profile
            .response(&request, 7, &amplified, &redactor)
            .err()
            .unwrap()
            .code,
        ErrorCode::LimitExceeded
    );
    let too_large = vec![b' '; MAX_RESPONSE + 1];
    assert_eq!(
        profile
            .response(&request, 7, &too_large, &redactor)
            .err()
            .unwrap()
            .code,
        ErrorCode::LimitExceeded
    );
    let mut decoder = SseDecoder::default();
    let comment = [b":".as_slice(), &vec![b' '; MAX_REQUEST - 2], b"\n"].concat();
    for _ in 0..4 {
        assert!(decoder.push(&comment).unwrap().is_empty());
    }
    assert_eq!(
        decoder.push(b"\n").err().unwrap().code,
        ErrorCode::LimitExceeded
    );
    assert!(decoder.finish().is_err());
}
