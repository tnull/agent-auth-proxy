use super::*;
use crate::{Argument, MAX_RESPONSE, Tool, VERSION};
use http::HeaderValue;
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

fn profile() -> Arc<Profile> {
    Arc::new(
        Profile::new(vec![Tool {
            name: "echo".into(),
            description: "Echo text".into(),
            arguments: BTreeMap::from([("message".into(), Argument::Text { max_length: 64 })]),
        }])
        .unwrap(),
    )
}
fn request(profile: &Profile, id: Option<Value>, method: &str, params: Value) -> Request {
    let mut value = json!({"jsonrpc":"2.0","method":method,"params":params});
    if let Some(id) = id {
        value["id"] = id;
    }
    profile
        .request(&serde_json::to_vec(&value).unwrap())
        .unwrap()
}
fn begin(context: &mut Context, request: Request, now: Instant) -> Exchange {
    context
        .begin(request, &aap_types::ids::random_id(16).unwrap(), now)
        .unwrap()
        .expect("live exchange expected")
}
fn init(profile: &Profile) -> Request {
    request(
        profile,
        Some(json!("init")),
        "initialize",
        json!({"protocolVersion":VERSION,"clientInfo":{"name":"fixture","version":"1"},"capabilities":{}}),
    )
}
fn call(profile: &Profile, id: &str) -> Request {
    request(
        profile,
        Some(json!(id)),
        "tools/call",
        json!({"name":"echo","arguments":{"message":"hello"}}),
    )
}
fn initialized(profile: &Profile) -> Request {
    request(profile, None, "notifications/initialized", json!({}))
}
fn headers(session: Option<&str>, sse: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static(if sse {
            "text/event-stream"
        } else {
            "application/json"
        }),
    );
    if let Some(session) = session {
        headers.insert("mcp-session-id", HeaderValue::from_str(session).unwrap());
    }
    headers
}
fn reply(
    context: &mut Context,
    exchange: &Exchange,
    result: Value,
    response_headers: &HeaderMap,
    now: Instant,
) -> Completion {
    let outbound: Value =
        serde_json::from_slice(&context.outgoing(exchange, now).unwrap().body).unwrap();
    let body =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":outbound["id"],"result":result})).unwrap();
    let mut decoder = context
        .start_response(
            exchange,
            StatusCode::OK,
            response_headers,
            &Redactor::new(&[b"private-key"]).unwrap(),
            now,
        )
        .unwrap();
    decoder.push(&body).unwrap();
    decoder.finish().unwrap()
}
fn init_result() -> Value {
    json!({"protocolVersion":VERSION,"capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}})
}
fn ready(profile: &Arc<Profile>, session: Option<&str>, now: Instant) -> Context {
    let mut context = Context::new(profile.clone(), now, now + Duration::from_secs(60))
        .expect("finite context must be created");
    let exchange = begin(&mut context, init(profile), now);
    let completion = reply(
        &mut context,
        &exchange,
        init_result(),
        &headers(session, false),
        now,
    );
    context.complete(exchange, completion, now).unwrap();
    let exchange = begin(&mut context, initialized(profile), now);
    let completion = context
        .start_response(
            &exchange,
            StatusCode::ACCEPTED,
            &HeaderMap::new(),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap()
        .finish()
        .unwrap();
    context.complete(exchange, completion, now).unwrap();
    context
}

#[test]
fn local_cancellation_is_one_shot_without_control_mapping_capacity() {
    let now = Instant::now();
    let profile = profile();
    let mut context = ready(&profile, Some("private-native"), now);
    let operation = aap_types::ids::random_id(16).unwrap();
    let exchange = context
        .begin(call(&profile, "owned"), &operation, now)
        .unwrap()
        .unwrap();
    let outgoing: Value =
        serde_json::from_slice(&context.outgoing(&exchange, now).unwrap().body).unwrap();
    let _ping_one = begin(
        &mut context,
        request(&profile, Some(json!(1)), "ping", json!({})),
        now,
    );
    let _ping_two = begin(
        &mut context,
        request(&profile, Some(json!(2)), "ping", json!({})),
        now,
    );
    context.next = 4097;
    let cancel = request(
        &profile,
        None,
        "notifications/cancelled",
        json!({"requestId":"owned","reason":"untrusted"}),
    );
    let cancelled = context.cancel_request(cancel, now).unwrap().unwrap();
    assert_eq!(cancelled.operation, operation);
    assert_eq!(
        cancelled.outgoing.headers["mcp-session-id"],
        "private-native"
    );
    let message: Value = serde_json::from_slice(&cancelled.outgoing.body).unwrap();
    assert_eq!(message["params"], json!({"requestId":outgoing["id"]}));
    assert!(context.outgoing(&exchange, now).is_err());
    assert!(context.cancel_operation(&operation, now).unwrap().is_none());
    context.abandon(exchange);
    assert!(context.cancel_operation(&operation, now).unwrap().is_none());
}

#[test]
fn only_local_operation_cancellation_aborts_initialization() {
    let now = Instant::now();
    let other = profile();
    let profile = profile();
    let mut context = Context::new(profile.clone(), now, now + Duration::from_secs(60)).unwrap();
    let operation = aap_types::ids::random_id(16).unwrap();
    let exchange = context
        .begin(init(&profile), &operation, now)
        .unwrap()
        .unwrap();
    assert!(
        context
            .cancel_request(
                request(
                    &other,
                    None,
                    "notifications/cancelled",
                    json!({"requestId":"init"})
                ),
                now
            )
            .is_err()
    );
    assert!(
        context
            .cancel_request(
                request(
                    &profile,
                    None,
                    "notifications/cancelled",
                    json!({"requestId":"init"})
                ),
                now
            )
            .unwrap()
            .is_none()
    );
    assert!(context.outgoing(&exchange, now).is_ok());
    assert!(context.cancel_operation(&operation, now).unwrap().is_none());
    assert_eq!(context.state(now), State::Invalid);
    assert!(context.outgoing(&exchange, now).is_err());
}

#[test]
fn handshake_commits_private_headers_only_after_complete_validated_results() {
    let now = Instant::now();
    let profile = profile();
    let mut context = Context::new(profile.clone(), now, now + Duration::from_secs(60))
        .expect("finite context must be created");
    assert_eq!(context.state(now), State::New);
    assert!(
        context
            .begin(
                call(&profile, "too-soon"),
                &aap_types::ids::random_id(16).unwrap(),
                now
            )
            .is_err()
    );
    let exchange = begin(&mut context, init(&profile), now);
    let outgoing = context.outgoing(&exchange, now).unwrap();
    assert!(!outgoing.headers.contains_key("mcp-session-id"));
    assert_eq!(
        outgoing.headers["accept"],
        "application/json, text/event-stream"
    );
    assert!(
        context
            .begin(init(&profile), &aap_types::ids::random_id(16).unwrap(), now)
            .is_err()
    );
    let completion = reply(
        &mut context,
        &exchange,
        init_result(),
        &headers(Some("private-session"), false),
        now,
    );
    assert_eq!(context.state(now), State::Initializing);
    assert!(
        context
            .begin(
                initialized(&profile),
                &aap_types::ids::random_id(16).unwrap(),
                now
            )
            .is_err()
    );
    assert!(!String::from_utf8_lossy(&completion.response().body).contains("private-session"));
    context.complete(exchange, completion, now).unwrap();
    assert_eq!(context.state(now), State::AwaitingInitialized);
    let notification = begin(&mut context, initialized(&profile), now);
    let outgoing = context.outgoing(&notification, now).unwrap();
    assert_eq!(outgoing.headers["mcp-session-id"], "private-session");
    assert!(outgoing.headers["mcp-session-id"].is_sensitive());
    assert_eq!(outgoing.headers["mcp-protocol-version"], VERSION);
    let completion = context
        .start_response(
            &notification,
            StatusCode::ACCEPTED,
            &HeaderMap::new(),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(context.state(now), State::AwaitingInitialized);
    let response = context.complete(notification, completion, now).unwrap();
    assert_eq!(response.status, StatusCode::ACCEPTED);
    assert!(response.body.is_empty());
    assert_eq!(context.state(now), State::Ready);
}

#[test]
fn contexts_ids_and_cancellations_are_owned_and_never_reassigned() {
    let now = Instant::now();
    let profile = profile();
    let mut first = ready(&profile, Some("first-private"), now);
    let mut second = ready(&profile, Some("second-private"), now);
    let operation = aap_types::ids::random_id(16).unwrap();
    let exchange = first
        .begin(call(&profile, "same-agent-id"), &operation, now)
        .unwrap()
        .unwrap();
    assert!(second.outgoing(&exchange, now).is_err());
    assert_eq!(second.state(now), State::Ready);
    assert!(
        first
            .begin(
                call(&profile, "same-agent-id"),
                &aap_types::ids::random_id(16).unwrap(),
                now
            )
            .is_err()
    );
    let id: Value = serde_json::from_slice(&first.outgoing(&exchange, now).unwrap().body).unwrap();
    let completion = reply(
        &mut first,
        &exchange,
        json!({"content":[]}),
        &headers(None, false),
        now,
    );
    let cancel = request(
        &profile,
        None,
        "notifications/cancelled",
        json!({"requestId":"same-agent-id"}),
    );
    let cancel = begin(&mut first, cancel, now);
    assert_eq!(cancel.cancellation_target(), Some(operation.as_str()));
    let cancel_body: Value =
        serde_json::from_slice(&first.outgoing(&cancel, now).unwrap().body).unwrap();
    assert_eq!(cancel_body["params"]["requestId"], id["id"]);
    assert!(
        first.complete(exchange, completion, now).is_err(),
        "cancelled results must not complete"
    );
    let complete = first
        .start_response(
            &cancel,
            StatusCode::ACCEPTED,
            &HeaderMap::new(),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap()
        .finish()
        .unwrap();
    first.complete(cancel, complete, now).unwrap();
    let next = begin(&mut first, call(&profile, "same-agent-id"), now);
    let next_id: Value = serde_json::from_slice(&first.outgoing(&next, now).unwrap().body).unwrap();
    assert_ne!(next_id["id"], id["id"]);
    first.abandon(next);
    let unknown = request(
        &profile,
        None,
        "notifications/cancelled",
        json!({"requestId":"unknown"}),
    );
    assert!(
        second
            .begin(unknown, &aap_types::ids::random_id(16).unwrap(), now)
            .unwrap()
            .is_none()
    );
    assert_eq!(second.close(now)["mcp-session-id"], "second-private");
    assert_eq!(second.state(now), State::Closed);
    assert!(second.close(now).is_empty());
}

#[test]
fn bad_statuses_headers_and_late_completions_cannot_restore_a_context() {
    let now = Instant::now();
    let profile = profile();
    for bad in ["", "space not allowed", &"x".repeat(1025)] {
        let mut context =
            Context::new(profile.clone(), now, now + Duration::from_secs(60)).unwrap();
        let exchange = begin(&mut context, init(&profile), now);
        assert!(
            context
                .start_response(
                    &exchange,
                    StatusCode::OK,
                    &headers(Some(bad), false),
                    &Redactor::new(&[]).unwrap(),
                    now
                )
                .is_err()
        );
        assert_eq!(context.state(now), State::Invalid);
    }
    for status in [
        StatusCode::NOT_FOUND,
        StatusCode::UNAUTHORIZED,
        StatusCode::FOUND,
    ] {
        let mut context = ready(&profile, Some("native"), now);
        let exchange = begin(&mut context, call(&profile, "x"), now);
        assert!(
            context
                .start_response(
                    &exchange,
                    status,
                    &headers(None, false),
                    &Redactor::new(&[]).unwrap(),
                    now
                )
                .is_err()
        );
        assert_eq!(context.state(now), State::Invalid);
        assert!(context.close(now).is_empty());
    }
    for (name, value) in [
        ("mcp-session-id", "replacement"),
        ("set-cookie", "auth=private"),
        ("content-encoding", "gzip"),
        ("trailer", "private"),
    ] {
        let mut context = ready(&profile, Some("native"), now);
        let exchange = begin(&mut context, call(&profile, "x"), now);
        let mut bad = headers(None, false);
        bad.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        assert!(
            context
                .start_response(
                    &exchange,
                    StatusCode::OK,
                    &bad,
                    &Redactor::new(&[]).unwrap(),
                    now
                )
                .is_err()
        );
        assert_eq!(context.state(now), State::Invalid);
    }
    let mut context = ready(&profile, None, now);
    let exchange = begin(&mut context, call(&profile, "x"), now);
    let completion = reply(
        &mut context,
        &exchange,
        json!({"content":[]}),
        &headers(None, false),
        now,
    );
    context.invalidate();
    assert!(context.complete(exchange, completion, now).is_err());
    assert_eq!(context.state(now), State::Invalid);
}

#[test]
fn json_and_sse_completion_keep_private_headers_and_echoes_out_of_results() {
    let now = Instant::now();
    let profile = profile();
    for sse in [false, true] {
        let mut context = ready(&profile, Some("private-session"), now);
        let exchange = begin(&mut context, call(&profile, "call"), now);
        let outbound: Value =
            serde_json::from_slice(&context.outgoing(&exchange, now).unwrap().body).unwrap();
        let json=serde_json::to_string(&json!({"jsonrpc":"2.0","id":outbound["id"],"result":{"content":[{"type":"text","text":"private-session private-key"}]}})).unwrap();
        let body = if sse {
            format!("id: private-session\ndata: {json}\n\n")
        } else {
            json
        };
        let mut decoder = context
            .start_response(
                &exchange,
                StatusCode::OK,
                &headers(None, sse),
                &Redactor::new(&[b"private-key"]).unwrap(),
                now,
            )
            .unwrap();
        for byte in body.bytes() {
            assert!(decoder.push(&[byte]).unwrap().is_empty());
        }
        let completion = decoder.finish().unwrap();
        let safe = context.complete(exchange, completion, now).unwrap();
        assert_eq!(
            safe.content_type,
            Some(if sse {
                "text/event-stream"
            } else {
                "application/json"
            })
        );
        assert!(String::from_utf8_lossy(&safe.body).contains("[redacted] [redacted]"));
        assert!(!String::from_utf8_lossy(&safe.body).contains("private-session"));
        assert!(!String::from_utf8_lossy(&safe.body).contains("private-key"));
    }
}

#[test]
fn framing_failures_and_extra_results_never_create_completions() {
    let now = Instant::now();
    let profile = profile();
    for sse in [false, true] {
        let mut context = ready(&profile, None, now);
        let exchange = begin(&mut context, call(&profile, "x"), now);
        let outbound: Value =
            serde_json::from_slice(&context.outgoing(&exchange, now).unwrap().body).unwrap();
        let message = serde_json::to_string(
            &json!({"jsonrpc":"2.0","id":outbound["id"],"result":{"content":[]}}),
        )
        .unwrap();
        let mut decoder = context
            .start_response(
                &exchange,
                StatusCode::OK,
                &headers(None, sse),
                &Redactor::new(&[]).unwrap(),
                now,
            )
            .unwrap();
        if sse {
            let event = format!("data: {message}\n\n");
            decoder.push(event.as_bytes()).unwrap();
            assert!(decoder.push(event.as_bytes()).is_err());
            assert!(decoder.finish().is_err());
        } else {
            decoder
                .push(&message.as_bytes()[..message.len() - 1])
                .unwrap();
            assert!(decoder.finish().is_err());
        }
        context.abandon(exchange);
        assert_eq!(context.state(now), State::Invalid);
    }
    let mut context = ready(&profile, None, now);
    let exchange = begin(&mut context, call(&profile, "x"), now);
    let mut decoder = context
        .start_response(
            &exchange,
            StatusCode::OK,
            &headers(None, false),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap();
    assert!(decoder.push(&vec![b' '; MAX_RESPONSE + 1]).is_err());
    assert!(decoder.push(b"{}").is_err());
    assert!(decoder.finish().is_err());
}

#[test]
fn lifecycle_deadlines_and_reserved_control_capacity_are_finite() {
    let now = Instant::now();
    let profile = profile();
    assert!(Context::new(profile.clone(), now, now).is_err());
    let mut context = Context::new(profile.clone(), now, now + Duration::from_secs(60)).unwrap();
    let exchange = begin(&mut context, init(&profile), now);
    assert!(
        context
            .outgoing(&exchange, now + Duration::from_secs(30))
            .is_err()
    );
    assert_eq!(context.state(now), State::Invalid);
    let mut context = ready(&profile, Some("native"), now);
    let mut exchanges = Vec::new();
    for index in 0..8 {
        exchanges.push(begin(
            &mut context,
            call(&profile, &format!("call-{index}")),
            now,
        ));
    }
    assert!(
        context
            .begin(
                call(&profile, "overflow"),
                &aap_types::ids::random_id(16).unwrap(),
                now
            )
            .is_err()
    );
    for index in 0..2 {
        exchanges.push(begin(
            &mut context,
            request(
                &profile,
                Some(json!(format!("ping-{index}"))),
                "ping",
                json!({}),
            ),
            now,
        ));
    }
    assert!(
        context
            .begin(
                request(&profile, Some(json!("ping-3")), "ping", json!({})),
                &aap_types::ids::random_id(16).unwrap(),
                now
            )
            .is_err()
    );
    assert!(
        context
            .outgoing(&exchanges[0], now + Duration::from_secs(60))
            .is_err()
    );
    assert_eq!(context.state(now), State::Invalid);
}

#[test]
fn server_ping_requires_live_parent_and_uses_provisional_session_custody() {
    let now = Instant::now();
    let profile = profile();
    let mut context = Context::new(profile.clone(), now, now + Duration::from_secs(60)).unwrap();
    let exchange = begin(&mut context, init(&profile), now);
    let mut decoder = context
        .start_response(
            &exchange,
            StatusCode::OK,
            &headers(Some("provisional-private"), true),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap();
    let pings = decoder
        .push(b"data: {\"jsonrpc\":\"2.0\",\"id\":\"remote-ping\",\"method\":\"ping\"}\n\n")
        .unwrap();
    assert_eq!(pings.len(), 1);
    let pong = context
        .ping_reply(&exchange, &decoder, &pings[0], now)
        .unwrap();
    assert_eq!(pong.headers["mcp-session-id"], "provisional-private");
    assert_eq!(
        serde_json::from_slice::<Value>(&pong.body).unwrap(),
        json!({"jsonrpc":"2.0","id":"remote-ping","result":{}})
    );
    assert!(
        context
            .ping_reply(&exchange, &decoder, &pings[0], now)
            .is_err(),
        "a ping response is usable once"
    );
    context.abandon(exchange);
    assert_eq!(context.state(now), State::Invalid);
    assert!(decoder.finish().is_err());
}

#[test]
fn poisoned_contexts_cannot_release_cleanup_headers() {
    let now = Instant::now();
    let profile = profile();
    let mut context = ready(&profile, Some("private-session"), now);
    let exchange = begin(&mut context, call(&profile, "x"), now);
    let mut decoder = context
        .start_response(
            &exchange,
            StatusCode::OK,
            &headers(None, true),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap();
    assert!(decoder.push(b"data: not-json\n\n").is_err());
    assert!(
        context.close(now).is_empty(),
        "poisoned session material must not escape through cleanup"
    );
    let mut expired = ready(&profile, Some("expired-session"), now);
    assert!(expired.close(now + Duration::from_secs(60)).is_empty());
    let mut dropped = ready(&profile, None, now);
    let exchange = begin(&mut dropped, call(&profile, "x"), now);
    let mut decoder = dropped
        .start_response(
            &exchange,
            StatusCode::OK,
            &headers(None, false),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap();
    drop(dropped);
    assert!(
        decoder.push(b"{}").is_err(),
        "a dropped owner must invalidate its retained decoder"
    );
}

#[test]
fn handshake_errors_duplicates_and_notification_bodies_fail_closed() {
    let now = Instant::now();
    let profile = profile();
    for duplicate in ["mcp-session-id", "content-type"] {
        let mut context =
            Context::new(profile.clone(), now, now + Duration::from_secs(60)).unwrap();
        let exchange = begin(&mut context, init(&profile), now);
        let mut bad = headers(Some("private-session"), false);
        bad.append(
            http::HeaderName::from_bytes(duplicate.as_bytes()).unwrap(),
            bad[duplicate].clone(),
        );
        assert!(
            context
                .start_response(
                    &exchange,
                    StatusCode::OK,
                    &bad,
                    &Redactor::new(&[]).unwrap(),
                    now
                )
                .is_err()
        );
        assert_eq!(context.state(now), State::Invalid);
    }
    let mut context = Context::new(profile.clone(), now, now + Duration::from_secs(60)).unwrap();
    let exchange = begin(&mut context, init(&profile), now);
    let outbound: Value =
        serde_json::from_slice(&context.outgoing(&exchange, now).unwrap().body).unwrap();
    let mut decoder = context
        .start_response(
            &exchange,
            StatusCode::OK,
            &headers(Some("private-session"), false),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap();
    decoder.push(&serde_json::to_vec(&json!({"jsonrpc":"2.0","id":outbound["id"],"error":{"code":-32603,"message":"private-session"}})).unwrap()).unwrap();
    let response = context
        .complete(exchange, decoder.finish().unwrap(), now)
        .unwrap();
    assert!(!String::from_utf8_lossy(&response.body).contains("private-session"));
    assert_eq!(context.state(now), State::Invalid);
    let mut context = Context::new(profile.clone(), now, now + Duration::from_secs(60)).unwrap();
    let exchange = begin(&mut context, init(&profile), now);
    let completion = reply(
        &mut context,
        &exchange,
        init_result(),
        &headers(None, false),
        now,
    );
    context.complete(exchange, completion, now).unwrap();
    let notification = begin(&mut context, initialized(&profile), now);
    let mut decoder = context
        .start_response(
            &notification,
            StatusCode::ACCEPTED,
            &HeaderMap::new(),
            &Redactor::new(&[]).unwrap(),
            now,
        )
        .unwrap();
    assert!(decoder.push(b"unexpected response body").is_err());
    assert_eq!(context.state(now), State::Invalid);
    assert!(decoder.finish().is_err());
}

#[test]
fn completion_tokens_and_issued_ids_cannot_cross_exchange_boundaries() {
    let now = Instant::now();
    let profile = profile();
    let mut first = ready(&profile, Some("first-private"), now);
    let mut second = ready(&profile, Some("second-private"), now);
    let a = begin(&mut first, call(&profile, "a"), now);
    let b = begin(&mut second, call(&profile, "b"), now);
    let result_a = reply(
        &mut first,
        &a,
        json!({"content":[]}),
        &headers(None, false),
        now,
    );
    let result_b = reply(
        &mut second,
        &b,
        json!({"content":[]}),
        &headers(None, false),
        now,
    );
    assert!(first.complete(a, result_b, now).is_err());
    assert!(second.complete(b, result_a, now).is_err());
    assert_eq!(first.state(now), State::Ready);
    assert_eq!(second.state(now), State::Ready);
    let mut context = ready(&profile, None, now);
    for _ in 3..=4096 {
        let exchange = begin(&mut context, call(&profile, "reused-client-id"), now);
        context.abandon(exchange);
    }
    assert_eq!(
        context
            .begin(
                call(&profile, "overflow"),
                &aap_types::ids::random_id(16).unwrap(),
                now
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::LimitExceeded
    );
    let mut initializing =
        Context::new(profile.clone(), now, now + Duration::from_secs(60)).unwrap();
    let exchange = begin(&mut initializing, init(&profile), now);
    let cancel = request(
        &profile,
        None,
        "notifications/cancelled",
        json!({"requestId":"init"}),
    );
    assert!(
        initializing
            .begin(cancel, &aap_types::ids::random_id(16).unwrap(), now)
            .unwrap()
            .is_none()
    );
    assert_eq!(initializing.state(now), State::Initializing);
    initializing.abandon(exchange);
    assert_eq!(initializing.state(now), State::Invalid);
}
