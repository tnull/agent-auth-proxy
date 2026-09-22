use super::*;
use aap_types::proxy::ForwardRequest;

fn forwarded(request: ExecuteRequest) -> ForwardRequest {
    ForwardRequest {
        request_id: request.request_id,
        auth_context: request.auth_context,
        method: request.method,
        target: request.target,
        headers: request.headers,
        body_base64: request.body_base64,
    }
}

#[tokio::test]
async fn connect_admission_checks_grants_and_addresses_without_secret_resolution() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    let authority = format!("fixture.test:{}", fixture.origin.address.port());
    session
        .admit_connect(authority.clone())
        .await
        .expect("enrolled CONNECT authority was not admitted");
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    for invalid in [
        "other.test:443".to_owned(),
        "fixture.test:443/path".into(),
        "fixture.test".into(),
        format!(
            "fixture.test:{}",
            if fixture.origin.address.port() == 443 {
                8443
            } else {
                443
            }
        ),
    ] {
        assert!(session.admit_connect(invalid).await.is_err());
    }
    let mut config = fixture.configuration();
    config.profiles[0].addresses = AddressPolicy::Public;
    assert!(
        Broker::new(config)
            .unwrap()
            .create_session(options())
            .unwrap()
            .admit_connect(authority.clone())
            .await
            .is_err(),
        "private DNS address bypassed admission"
    );
    let mut restricted = options();
    restricted.resources.clear();
    assert!(
        broker
            .create_session(restricted)
            .unwrap()
            .admit_connect(authority.clone())
            .await
            .is_err()
    );
    broker.revoke(&session).unwrap();
    assert!(session.admit_connect(authority).await.is_err());
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn connect_admission_requires_recording_before_ca_access_is_allowed() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    let authority = format!("fixture.test:{}", fixture.origin.address.port());
    fixture.recorder.set_available(false);
    assert!(
        matches!(session.admit_connect(authority.clone()).await,Err(error) if error.code==ErrorCode::ObservationUnavailable),
        "required observation outage still allowed signing admission"
    );
    fixture.recorder.set_available(true);
    session.admit_connect(authority.clone()).await.unwrap();
    let records = serde_json::to_value(fixture.recorder.read(None, 256).unwrap()).unwrap();
    assert!(records["records"].as_array().unwrap().iter().any(
        |record| record["event"]["data"]["event_type"] == "connect_admission"
            && record["event"]["data"]["authority"] == authority
    ));
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn forwarded_requests_select_a_unique_profile_and_keep_existing_deduplication() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    let request = forwarded(fixture.request());
    let response = session
        .forward(request.clone())
        .await
        .expect("forwarding never reached the broker pipeline");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "data: [redacted]\n\n"
    );
    assert_eq!(
        session.forward(request.clone()).await.unwrap().headers()["x-aap-operation-state"],
        "existing"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    let mut denied = request.clone();
    denied.request_id = aap_types::ids::random_id(16).unwrap();
    denied.target = denied.target.replace("fixture.test", "other.test");
    assert!(session.forward(denied).await.is_err());
    let mut configuration = fixture.configuration();
    let mut duplicate = configuration.profiles[0].clone();
    duplicate.id = "other".into();
    duplicate.auth = Authentication::None;
    configuration.profiles.push(duplicate);
    let broker = Broker::new(configuration).unwrap();
    let mut granted = options();
    granted.resources.push("other".into());
    assert!(
        broker
            .create_session(granted)
            .unwrap()
            .forward(request)
            .await
            .is_err(),
        "ambiguous route silently picked an account"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
}
