#![cfg(target_os = "linux")]
#[path = "../../support/fixture.rs"]
mod fixture;
use aap_types::{AgentService, BoxFuture, ErrorCode, Result, profile::LoginEncoding};
use reuse_embedded::{Host, Settings, scenarios};
use std::{net::SocketAddr, sync::Arc, time::Duration};

struct Fixed(SocketAddr);
impl aap_transport::Resolver for Fixed {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            assert_eq!(host, "fixture.test");
            assert_eq!(port, self.0.port());
            Ok(vec![self.0])
        })
    }
}

#[tokio::test]
async fn embedded_host_joins_upstream_work_while_response_is_retained() {
    use base64::Engine;
    use http_body_util::BodyExt;
    let fixture = fixture::Fixture::new(LoginEncoding::Form).await;
    let host = Host::open(
        Settings {
            directory: Arc::new(
                aap_config::PrivateDir::open(&fixture.root().join("s"), false).unwrap(),
            ),
            catalog: fixture.catalog.clone(),
            profiles: fixture.profiles.clone(),
            root_certificates: vec![fixture.origin.certificate.to_vec()],
            resolver: Arc::new(Fixed(fixture.origin.address)),
        },
        fixture::Fixture::key(),
        tokio::runtime::Handle::current(),
    )
    .await
    .unwrap();
    let session = host
        .broker
        .create_session(aap_engine::SessionOptions {
            resources: vec!["provider".into()],
            items: None,
            lifetime: Duration::from_secs(60),
            require_approval: false,
            require_observation: true,
        })
        .unwrap();
    let input = aap_types::ExecuteRequest {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "provider".into(), auth_context: None, method: "POST".into(),
        target: format!("{}/v1/chat/completions", fixture.origin.origin()),
        headers: vec![("content-type".into(), "application/json".into())],
        body_base64: base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({"model":"fixture", "messages":[{"role":"user", "content":"cancel"}], "stream":true})).unwrap()),
    };
    let held = session.execute(input).await.unwrap();
    assert_eq!(fixture.origin.active_connections(), 1);
    assert_eq!(
        host.http_drivers.status().tasks_pending,
        1,
        "host did not retain its transport owner"
    );
    host.broker.close().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let joined = host.http_drivers.wait_until_idle(deadline).await;
    assert_eq!(joined.tasks_pending, 0);
    assert!(!joined.join_failed);
    tokio::time::timeout_at(deadline, async {
        while fixture.origin.active_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("embedded host left an upstream socket alive");
    assert!(held.into_body().collect().await.is_err());
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn external_sqlcipher_host_runs_the_shared_scenarios_without_a_daemon() {
    for encoding in [LoginEncoding::Form, LoginEncoding::Json] {
        let fixture = fixture::Fixture::new(encoding).await;
        let settings = Settings {
            directory: Arc::new(
                aap_config::PrivateDir::open(&fixture.root().join("s"), false).unwrap(),
            ),
            catalog: fixture.catalog.clone(),
            profiles: fixture.profiles.clone(),
            root_certificates: vec![fixture.origin.certificate.to_vec()],
            resolver: Arc::new(Fixed(fixture.origin.address)),
        };
        let host = Host::open(
            settings,
            fixture::Fixture::key(),
            tokio::runtime::Handle::current(),
        )
        .await
        .expect("trusted public composition is unavailable");
        let options = || aap_engine::SessionOptions {
            resources: vec!["provider".into(), "website".into()],
            items: None,
            lifetime: Duration::from_secs(60),
            require_approval: false,
            require_observation: true,
        };
        let first = host.broker.create_session(options()).unwrap();
        let second = host.broker.create_session(options()).unwrap();
        let retained = [first.clone(), second.clone()];
        let report = tokio::time::timeout(
            Duration::from_secs(30),
            scenarios::run(
                Arc::new(first.clone()),
                Arc::new(second.clone()),
                &fixture.origin.origin(),
            ),
        )
        .await
        .unwrap()
        .expect("shared scenarios are unavailable");
        let mut records = vec![];
        let mut cursor = None;
        loop {
            let batch = host.recorder.read(cursor.as_ref(), 256).unwrap();
            assert!(batch.gap.is_none());
            if batch.records.is_empty() {
                break;
            }
            assert!(records.len() < 4096);
            records.extend(batch.records);
            cursor = Some(batch.cursor);
        }
        fixture.verify(&serde_json::to_value(report).unwrap(), &records);
        host.broker.revoke(&first).unwrap();
        host.broker.revoke(&second).unwrap();
        for session in retained {
            assert!(
                matches!(session.search_items(aap_types::SearchItems{uri:format!("{}/login",fixture.origin.origin()),query:None,cursor:None}).await,Err(error) if error.code==ErrorCode::SessionInvalid)
            );
        }
        // Keep per-session revocation evidence above. Broker closure must also
        // invalidate a still-live handle and prevent future admission.
        let live = host.broker.create_session(options()).unwrap();
        let retained = live.clone();
        host.broker.close().unwrap();
        assert!(host.broker.is_closed());
        host.broker.close().unwrap();
        assert!(matches!(host.broker.create_session(options()),
            Err(error) if error.code == ErrorCode::SessionInvalid));
        for session in [live, retained] {
            assert!(
                matches!(session.search_items(aap_types::SearchItems{uri:format!("{}/login",fixture.origin.origin()),query:None,cursor:None}).await,Err(error) if error.code==ErrorCode::SessionInvalid)
            );
        }
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 10);
    }
}

#[tokio::test]
async fn opening_a_host_never_creates_or_replaces_its_store() {
    let fixture = fixture::Fixture::new(LoginEncoding::Form).await;
    let settings = |directory: std::path::PathBuf| Settings {
        directory: Arc::new(aap_config::PrivateDir::open(&directory, false).unwrap()),
        catalog: fixture.catalog.clone(),
        profiles: fixture.profiles.clone(),
        root_certificates: vec![fixture.origin.certificate.to_vec()],
        resolver: Arc::new(Fixed(fixture.origin.address)),
    };
    let runtime = tokio::runtime::Handle::current();
    assert!(matches!(Host::open(settings(fixture.root().join("s")),
        aap_secrets::SecretBytes::new(vec![42; 32]).unwrap(), runtime.clone()).await,
        Err(error) if error.code == ErrorCode::VaultUnavailable));
    // The wrong key must not damage or replace the existing encrypted store.
    let host = Host::open(
        settings(fixture.root().join("s")),
        fixture::Fixture::key(),
        runtime.clone(),
    )
    .await
    .unwrap();
    drop(host);
    let missing = fixture.root().join("absent-store");
    aap_config::PrivateDir::open(&missing, true).unwrap();
    assert!(
        matches!(Host::open(settings(missing.clone()), fixture::Fixture::key(), runtime).await,
        Err(error) if error.code == ErrorCode::VaultUnavailable)
    );
    assert_eq!(std::fs::read_dir(missing).unwrap().count(), 0);
    assert_eq!(fixture.origin.accepted_connections(), 0);
}
