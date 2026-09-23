use super::super::remote_mcp as upstream;
use super::{boundary::Boundary, connect, *};

async fn tool(
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
    upstream::safe(&serde_json::to_vec(&value).unwrap());
    value["tool"].clone()
}
fn success(value: Value) -> Value {
    assert_eq!(value["isError"], false);
    value["structuredContent"].clone()
}
fn response(value: Value, status: u16) -> Vec<u8> {
    let value = success(value);
    assert_eq!(value["kind"], "response");
    assert_eq!(value["status"], status);
    assert_eq!(value["complete"], true);
    for header in value["headers"].as_array().unwrap() {
        assert_ne!(header[0], "set-cookie");
        assert_ne!(header[0], "mcp-session-id");
    }
    let bytes = STANDARD
        .decode(value["body_base64"].as_str().unwrap())
        .unwrap();
    upstream::safe(&bytes);
    bytes
}
fn denied(value: Value, code: ErrorCode) {
    assert_eq!(value["isError"], true);
    assert_eq!(value["structuredContent"]["code"], json!(code));
}
fn echo(bytes: &[u8], account: &str, text: &str) {
    let value = upstream::decoded(bytes);
    assert_eq!(value["id"], "agent-call");
    assert_eq!(
        value["result"]["content"][0]["text"],
        format!("{account}:{text} [redacted] [redacted]")
    );
}

#[tokio::test]
#[ignore = "requires the explicit Linux confinement setup in docs/confinement.md"]
async fn confined_remote_mcp_shares_private_contexts_across_stdio_and_connect() {
    let _exclusive = LAUNCH_TEST_LOCK.lock().await;
    for sse in [false, true] {
        remote(sse).await;
    }
}

async fn remote(sse: bool) {
    let mut fixture = upstream::fixture(sse).await;
    let root = super::super::interception::enroll_ca(&mut fixture).await;
    let (mut daemon, ready) = fixture.start().await;
    let boundary = Boundary::new(
        &fixture,
        &daemon,
        &ready,
        json!({"resources":["mcp-first"],"lifetime_seconds":120}),
        &[fixture.origin.address],
    )
    .await;
    connect::connections(&fixture, 2).await;
    let (status, other) = local(
        boundary.control.clone(),
        "/aap/operator/v1/session/create",
        json!({"resources":["mcp-second"],"lifetime_seconds":120}),
    )
    .await;
    assert!(status.is_success());
    let other: SessionAttachment = serde_json::from_value(other).unwrap();
    let mut processes = [
        boundary.spawn(0).await,
        boundary.spawn(1).await,
        Probe::spawn(
            &boundary.executable,
            Some(&fixture.root.join("r").join(other.ingress_socket)),
        )
        .await,
    ];
    let tunnel = |message: Value| {
        connect::action(
            &fixture,
            &root,
            "POST",
            "/mcp",
            "application/json",
            serde_json::to_vec(&message).unwrap(),
        )
    };
    denied(
        tool(
            &boundary,
            &mut processes[0],
            0,
            "request.execute",
            upstream::input(&fixture, "mcp-first", upstream::call("early")),
        )
        .await,
        ErrorCode::RequestConflict,
    );
    denied(
        tool(
            &boundary,
            &mut processes[0],
            0,
            "request.execute",
            upstream::input(&fixture, "mcp-second", upstream::initialize()),
        )
        .await,
        ErrorCode::PolicyDenied,
    );
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    let mut completed = vec![];
    for (index, process) in processes.iter_mut().enumerate() {
        let session = index % 2;
        let resource = if index == 2 {
            "mcp-second"
        } else {
            "mcp-first"
        };
        let (first, initialized) = if index == 1 {
            let first = connect::response(
                &boundary
                    .action(process, session, tunnel(upstream::initialize()))
                    .await,
                200,
            );
            let request = upstream::input(&fixture, resource, upstream::initialized());
            completed.push(request.request_id.clone());
            let initialized = response(
                tool(&boundary, process, session, "request.execute", request).await,
                202,
            );
            (first, initialized)
        } else {
            let request = upstream::input(&fixture, resource, upstream::initialize());
            completed.push(request.request_id.clone());
            let first = response(
                tool(&boundary, process, session, "request.execute", request).await,
                200,
            );
            let initialized = connect::response(
                &boundary
                    .action(process, session, tunnel(upstream::initialized()))
                    .await,
                202,
            );
            (first, initialized)
        };
        assert_eq!(upstream::decoded(&first)["id"], "agent-init");
        assert_eq!(
            upstream::decoded(&first)["result"]["protocolVersion"],
            "2025-11-25"
        );
        assert!(initialized.is_empty());
        let bytes = connect::response(
            &boundary
                .action(process, session, tunnel(upstream::call("confined")))
                .await,
            200,
        );
        echo(
            &bytes,
            if index == 2 { "second" } else { "first" },
            "confined",
        );
    }
    let before = fixture.origin.requests.lock().unwrap().len();
    assert_eq!(before, 9 + 6 * usize::from(sse));
    for (name, status, code) in [
        ("mcp-session-id", 403, "policy_denied"),
        ("mcp-protocol-version", 503, "inspection_unavailable"),
    ] {
        let mut forged = tunnel(upstream::call("forged"));
        forged["request"]["headers"]
            .as_array_mut()
            .unwrap()
            .push(json!([name, "attacker-selected"]));
        let bytes = connect::response(&boundary.action(&mut processes[0], 0, forged).await, status);
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["code"],
            code
        );
    }
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), before);
    connect::connections(&fixture, before + 2).await;

    let deleted = boundary
        .action(
            &mut processes[0],
            0,
            connect::action(
                &fixture,
                &root,
                "DELETE",
                "/mcp",
                "application/json",
                vec![],
            ),
        )
        .await;
    assert!(connect::response(&deleted, 204).is_empty());
    assert!(
        deleted["headers"]
            .as_array()
            .unwrap()
            .contains(&json!(["x-aap-remote-cleanup", "confirmed"]))
    );
    denied(
        tool(
            &boundary,
            &mut processes[0],
            0,
            "request.execute",
            upstream::input(&fixture, "mcp-first", upstream::call("closed")),
        )
        .await,
        ErrorCode::RequestConflict,
    );
    echo(
        &connect::response(
            &boundary
                .action(
                    &mut processes[1],
                    1,
                    tunnel(upstream::call("other-session")),
                )
                .await,
            200,
        ),
        "first",
        "other-session",
    );
    let before = fixture.origin.requests.lock().unwrap().len();
    let collector = boundary.tiny_collector(1).await;
    let refused = boundary
        .action(
            &mut processes[1],
            1,
            tunnel(upstream::call("recording-denied")),
        )
        .await;
    assert_eq!(refused["phase"], "connect");
    assert_eq!(refused["status"], 503);
    assert_eq!(refused["tls_verified"], false);
    denied(
        tool(
            &boundary,
            &mut processes[1],
            1,
            "request.execute",
            upstream::input(&fixture, "mcp-first", upstream::call("recording-denied")),
        )
        .await,
        ErrorCode::ObservationUnavailable,
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), before);
    connect::connections(&fixture, before + 2).await;
    boundary.remove_collector(collector).await;
    let resumed = upstream::input(&fixture, "mcp-first", upstream::call("resumed"));
    completed.push(resumed.request_id.clone());
    echo(
        &response(
            tool(&boundary, &mut processes[1], 1, "request.execute", resumed).await,
            200,
        ),
        "first",
        "resumed",
    );

    let mut approval = boundary.approval_process(&fixture, &["mcp-first"]).await;
    let before = fixture.origin.requests.lock().unwrap().len();
    denied(
        tool(
            &boundary,
            &mut approval,
            0,
            "request.execute",
            upstream::input(&fixture, "mcp-first", upstream::initialize()),
        )
        .await,
        ErrorCode::InteractionUnavailable,
    );
    let bytes = connect::response(
        &boundary
            .action(&mut approval, 0, tunnel(upstream::initialize()))
            .await,
        503,
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["code"],
        "interaction_unavailable"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), before);
    connect::connections(&fixture, before + 2).await;
    approval.finish().await;

    let dropped = upstream::input(&fixture, "mcp-first", upstream::call("drop"));
    let lost_id = dropped.request_id.clone();
    denied(
        tool(
            &boundary,
            &mut processes[1],
            1,
            "request.execute",
            dropped.clone(),
        )
        .await,
        ErrorCode::OutcomeUnknown,
    );
    let state = success(
        tool(
            &boundary,
            &mut processes[1],
            1,
            "request.status",
            json!({"request_id":lost_id}),
        )
        .await,
    );
    assert_eq!(state["state"], "outcome_unknown");
    let repeated = success(tool(&boundary, &mut processes[1], 1, "request.execute", dropped).await);
    assert_eq!(repeated["kind"], "operation");
    assert_eq!(repeated["operation"]["state"], "outcome_unknown");
    let expected = 13 + 8 * usize::from(sse);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), expected);
    connect::connections(&fixture, expected + 2).await;
    {
        let requests = fixture.origin.requests.lock().unwrap();
        let native: std::collections::BTreeSet<_> = requests
            .iter()
            .filter_map(|request| request.headers.get("mcp-session-id"))
            .map(|value| value.as_bytes())
            .collect();
        assert_eq!(
            native.len(),
            3,
            "sandbox sessions shared upstream authority"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| serde_json::from_slice::<Value>(&request.body)
                    .is_ok_and(|message| message["params"]["arguments"]["text"] == "drop"))
                .count(),
            1
        );
    }
    let (records, gaps) = boundary.observations().await;
    assert!(!gaps.is_empty());
    for id in completed {
        connect::endings(&records, &id, true);
    }
    connect::endings(&records, &lost_id, false);
    assert!(
        records
            .iter()
            .any(|record| record.event.parent_request_id.is_some()),
        "cleanup/control subrequests lack correlation"
    );
    for record in records {
        upstream::safe(&serde_json::to_vec(&record).unwrap());
        if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
            upstream::safe(&STANDARD.decode(body_base64).unwrap());
        }
    }
    boundary.assert_no_bypass();
    for process in processes {
        process.finish().await;
    }
    stop(&mut daemon).await;
}
