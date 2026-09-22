use super::*;
use aap_policy::{TcpLimits, TcpProfile};

#[tokio::test]
async fn tcp_grants_are_credential_free_and_cannot_bypass_inspected_profiles() {
    let fixture = Fixture::new().await;
    let profile = TcpProfile {
        id: "raw-fixture".into(),
        endpoint: "raw.test:9000".into(),
        addresses: AddressPolicy::Pinned(vec!["127.0.0.1".parse().unwrap()]),
        limits: TcpLimits::default(),
        inspection: aap_types::stream::Inspection::PlaintextBytes,
        require_approval: false,
        require_observation: true,
    };
    let mut configuration = fixture.configuration();
    configuration.tcp_profiles.push(profile.clone());
    let broker = Broker::new(configuration).unwrap();
    let mut options = options();
    options.resources = vec![profile.id.clone()];
    let session = broker
        .create_session(options)
        .expect("enrolled TCP resource cannot be granted");
    let mut request = fixture.request();
    request.resource = profile.id.clone();
    assert!(session.execute(request).await.is_err());
    assert!(
        session
            .search_items(SearchItems {
                uri: fixture.origin.origin(),
                query: None,
                cursor: None
            })
            .await
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());

    let mut configuration = fixture.configuration();
    let mut collision = profile.clone();
    collision.endpoint = format!("fixture.test:{}", fixture.origin.address.port());
    configuration.tcp_profiles.push(collision);
    assert!(
        Broker::new(configuration).is_err(),
        "raw endpoint bypasses inspected provider"
    );
    let mut configuration = fixture.configuration();
    configuration.catalog.items[0].profile = profile.id.clone();
    configuration.tcp_profiles.push(profile);
    assert!(
        Broker::new(configuration).is_err(),
        "credential item attached to raw TCP"
    );
}
