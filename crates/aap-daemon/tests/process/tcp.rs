use super::*;
use aap_policy::{TcpLimits, TcpProfile};

#[tokio::test]
async fn tcp_configuration_is_validated_and_cannot_be_used_as_http() {
    let mut fixture = Fixture::new().await;
    let directory = fixture.root.join("c");
    let validate = || {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-auth-proxy"));
        command
            .arg("validate")
            .arg(&directory)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        command
    };
    // Existing schema-1 input need not name TCP resources at all.
    let mut old = serde_json::to_value(&fixture.config).unwrap();
    old.as_object_mut().unwrap().remove("tcp_profiles");
    let old: DaemonConfig = aap_types::json::decode(&serde_json::to_vec(&old).unwrap()).unwrap();
    assert!(old.tcp_profiles.is_empty());
    let raw = TcpProfile {
        id: "raw-fixture".into(),
        endpoint: "raw.test:9000".into(),
        addresses: AddressPolicy::Pinned(vec!["127.0.0.1".parse().unwrap()]),
        limits: TcpLimits::default(),
        inspection: aap_types::stream::Inspection::PlaintextBytes,
        require_approval: false,
        require_observation: true,
    };
    fixture.config.tcp_profiles.push(raw.clone());
    fixture.write();
    assert!(validate().output().await.unwrap().status.success());
    fixture.config.tcp_profiles[0].endpoint =
        format!("fixture.test:{}", fixture.origin.address.port());
    fixture.write();
    assert!(
        !validate().output().await.unwrap().status.success(),
        "daemon validation admitted raw access to inspected provider"
    );
    fixture.config.tcp_profiles[0] = raw;
    fixture.write();
    let (mut child, ready) = fixture.start().await;
    let (status, attachment) = local(
        fixture.root.join("r").join(ready.control_socket),
        "/aap/operator/v1/session/create",
        json!({"resources":["raw-fixture"],"lifetime_seconds":60}),
    )
    .await;
    assert!(status.is_success());
    let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
    let client = aap_client::DaemonSessionClient::new(
        fixture.root.join("r").join(attachment.ingress_socket),
    );
    let mut request = fixture.request();
    request.resource = "raw-fixture".into();
    assert!(client.execute(request).await.is_err());
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    stop(&mut child).await;
}
