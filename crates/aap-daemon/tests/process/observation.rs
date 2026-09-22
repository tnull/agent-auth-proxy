use super::*;

async fn subscribe(control: &std::path::Path, session: &str, class: &str, lifetime: u64) -> Value {
    let (status, attachment) = local(
        control.to_path_buf(),
        "/aap/operator/v1/observation/create",
        json!({
            "scope":{"sessions":[session],"views":["upstream"],"classes":[class]},
            "limits":{"max_events":128,"max_bytes":1048576},"lifetime_seconds":lifetime
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "scoped observer enrollment failed: {attachment}"
    );
    attachment
}
#[tokio::test]
async fn collectors_have_private_scopes_cursors_and_revocable_attachments() {
    let fixture = Fixture::new().await;
    let (mut child, ready) = fixture.start().await;
    let root = fixture.root.join("r");
    let control = root.join(&ready.control_socket);
    let mut sessions = Vec::new();
    for _ in 0..2 {
        let (status, attachment) = local(
            control.clone(),
            "/aap/operator/v1/session/create",
            json!({"resources":["provider"],"lifetime_seconds":60}),
        )
        .await;
        assert!(status.is_success());
        sessions.push(serde_json::from_value::<SessionAttachment>(attachment).unwrap());
    }
    let first = subscribe(&control, &sessions[0].session_id, "content", 60).await;
    let second = subscribe(&control, &sessions[1].session_id, "content", 60).await;
    let metadata = subscribe(&control, &sessions[0].session_id, "metadata", 60).await;
    let paths: Vec<_> = [&first, &second, &metadata]
        .into_iter()
        .map(|attachment| root.join(attachment["observation_socket"].as_str().unwrap()))
        .collect();
    for (index, session) in sessions.iter().enumerate() {
        let client = aap_client::DaemonSessionClient::new(root.join(&session.ingress_socket));
        let mut input = fixture.request();
        input.body_base64=STANDARD.encode(json!({"model":"fixture","messages":[{"role":"user","content":format!("session-{index}-only")}],"stream":true}).to_string());
        client
            .execute(input)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    let mut batches = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let (status, batch) =
            local(path.clone(), "/aap/observe/v1/read", json!({"limit":128})).await;
        assert!(status.is_success());
        let deliveries = batch["deliveries"].as_array().unwrap();
        assert!(!deliveries.is_empty());
        for delivery in deliveries {
            let event = &delivery["record"]["event"];
            assert_eq!(
                event["session_id"],
                sessions[usize::from(index == 1)].session_id
            );
            assert_eq!(event["view"], "upstream");
            assert_eq!(event["data"]["event_type"] == "content_chunk", index != 2);
            if index != 2 {
                let bytes = STANDARD
                    .decode(event["data"]["body_base64"].as_str().unwrap())
                    .unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains("synthetic-daemon-key"));
                assert!(!text.contains(&format!("session-{}-only", 1 - index)));
            }
        }
        batches.push(batch);
    }
    for method in ["/aap/observe/v1/read", "/aap/observe/v1/ack"] {
        let body = if method.ends_with("read") {
            json!({"cursor":batches[0]["cursor"],"limit":128})
        } else {
            batches[0]["cursor"].clone()
        };
        assert!(
            !local(paths[1].clone(), method, body).await.0.is_success(),
            "foreign cursor crossed a subscription boundary"
        );
    }
    assert!(
        !local(
            paths[0].clone(),
            "/aap/operator/v1/session/create",
            json!({"resources":["provider"],"lifetime_seconds":60})
        )
        .await
        .0
        .is_success()
    );
    assert!(
        !local(
            paths[0].clone(),
            "/aap/observe/v1/read",
            json!({"limit":128,"session_id":sessions[1].session_id})
        )
        .await
        .0
        .is_success()
    );
    assert!(
        local(
            paths[0].clone(),
            "/aap/observe/v1/ack",
            batches[0]["cursor"].clone()
        )
        .await
        .0
        .is_success()
    );
    assert_eq!(
        local(
            paths[1].clone(),
            "/aap/observe/v1/read",
            json!({"limit":128})
        )
        .await
        .1,
        batches[1]
    );
    assert!(
        local(
            control.clone(),
            "/aap/operator/v1/observation/revoke",
            json!({"subscription_id":first["subscription_id"]})
        )
        .await
        .0
        .is_success()
    );
    assert!(tokio::net::UnixStream::connect(&paths[0]).await.is_err());
    assert!(
        local(
            control.clone(),
            "/aap/operator/v1/session/revoke",
            json!({"session_id":sessions[1].session_id})
        )
        .await
        .0
        .is_success()
    );
    assert!(tokio::net::UnixStream::connect(&paths[1]).await.is_err());
    assert!(
        local(
            paths[2].clone(),
            "/aap/observe/v1/read",
            json!({"limit":128})
        )
        .await
        .0
        .is_success()
    );
    let expires = subscribe(&control, &sessions[0].session_id, "content", 1).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    local(control.clone(), "/aap/operator/v1/status", json!({})).await;
    assert!(
        tokio::net::UnixStream::connect(root.join(expires["observation_socket"].as_str().unwrap()))
            .await
            .is_err()
    );
    let mut invalid = fixture.config.clone();
    invalid.configuration_revision = 2;
    let directory = aap_config::PrivateDir::open(&fixture.root.join("c"), false).unwrap();
    directory
        .write_atomic(
            "daemon.json",
            &serde_json::to_vec(&invalid).unwrap(),
            1024 * 1024,
        )
        .unwrap();
    assert!(
        !local(control.clone(), "/aap/operator/v1/reload", json!({}))
            .await
            .0
            .is_success()
    );
    assert!(
        local(
            paths[2].clone(),
            "/aap/observe/v1/read",
            json!({"limit":128})
        )
        .await
        .0
        .is_success()
    );
    let mut catalog = fixture.catalog.clone();
    catalog.configuration_revision = 2;
    directory
        .write_atomic(
            "catalog.json",
            &serde_json::to_vec(&catalog).unwrap(),
            1024 * 1024,
        )
        .unwrap();
    assert!(
        local(control, "/aap/operator/v1/reload", json!({}))
            .await
            .0
            .is_success()
    );
    assert!(tokio::net::UnixStream::connect(&paths[2]).await.is_err());
    stop(&mut child).await;
}

#[tokio::test]
async fn full_required_collector_prevents_upstream_dispatch_until_revoked() {
    let fixture = Fixture::new().await;
    let (mut child, ready) = fixture.start().await;
    let root = fixture.root.join("r");
    let control = root.join(&ready.control_socket);
    let (_, session) = local(
        control.clone(),
        "/aap/operator/v1/session/create",
        json!({"resources":["provider"],"lifetime_seconds":60}),
    )
    .await;
    let session: SessionAttachment = serde_json::from_value(session).unwrap();
    let (status,attachment)=local(control.clone(),"/aap/operator/v1/observation/create",json!({
        "scope":{"sessions":[session.session_id],"views":["agent","upstream"],"classes":["metadata"]},
        "limits":{"max_events":1,"max_bytes":8192},"lifetime_seconds":60
    })).await;
    assert!(status.is_success());
    let client = aap_client::DaemonSessionClient::new(root.join(&session.ingress_socket));
    assert!(
        matches!(client.execute(fixture.request()).await,Err(error) if error.code==ErrorCode::ObservationUnavailable)
    );
    assert!(
        fixture.origin.requests.lock().unwrap().is_empty(),
        "required collector overflow allowed upstream dispatch"
    );
    let (_, batch) = local(
        root.join(attachment["observation_socket"].as_str().unwrap()),
        "/aap/observe/v1/read",
        json!({"limit":128}),
    )
    .await;
    assert!(batch["deliveries"].as_array().unwrap().is_empty());
    assert!(
        batch["gap"].is_object(),
        "required rejection hid the missing observations"
    );
    assert!(
        local(
            control,
            "/aap/operator/v1/observation/revoke",
            json!({"subscription_id":attachment["subscription_id"]})
        )
        .await
        .0
        .is_success()
    );
    client
        .execute(fixture.request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    stop(&mut child).await;
}
