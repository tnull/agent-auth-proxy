use super::*;
use aap_test_support::{Origin, Reply};
use http_body_util::BodyExt;

fn request(origin: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method("POST")
        .uri(format!("{origin}/messages"))
        .header("authorization", "Bearer synthetic-key")
        .body(Bytes::from_static(b"synthetic-body"))
        .unwrap()
}

#[test]
fn endpoints_bind_https_authority_to_the_admitted_port() {
    let address = "127.0.0.1:443".parse().unwrap();
    assert!(
        Endpoint::new("https://fixture.test", address).is_ok(),
        "valid admitted endpoint rejected"
    );
    for origin in [
        "http://fixture.test",
        "https://user@fixture.test",
        "https://fixture.test/path",
        "https://fixture.test:444",
        "https://fixture.test?query=1",
        "https://fixture.test:",
        "https://fixture.test:abc",
        "https://fixture.test:65536",
        "https://fixture.test.",
    ] {
        assert!(Endpoint::new(origin, address).is_err());
    }
}

#[tokio::test]
async fn tls_name_is_verified_even_when_the_issuer_is_trusted() {
    let origin = Origin::spawn(Reply::body("ok")).await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    let wrong_name = format!("https://wrong.test:{}", origin.address.port());
    let result = transport
        .execute(
            Endpoint::new(&wrong_name, origin.address).unwrap(),
            request(&wrong_name),
            Limits::default(),
            Cancellation::default(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::UpstreamUnavailable));
    assert!(origin.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn preflight_rejects_conflicting_framing_limits_and_cancelled_work() {
    let origin = Origin::spawn(Reply::body("ok")).await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    for (name, value) in [
        ("host", "wrong.test"),
        ("content-length", "999"),
        ("transfer-encoding", "chunked"),
        ("connection", "authorization"),
    ] {
        let mut request = request(&origin.origin());
        request.headers_mut().insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_static(value),
        );
        let result = transport
            .execute(
                Endpoint::new(&origin.origin(), origin.address).unwrap(),
                request,
                Limits::default(),
                Cancellation::default(),
            )
            .await;
        assert!(matches!(result, Err(error) if error.code == ErrorCode::RequestInvalid));
    }
    let limits = Limits {
        max_request_bytes: 1,
        ..Limits::default()
    };
    let result = transport
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            request(&origin.origin()),
            limits,
            Cancellation::default(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::LimitExceeded));
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let result = transport
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            request(&origin.origin()),
            Limits::default(),
            cancellation,
        )
        .await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::UpstreamUnavailable));
    assert!(origin.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn idle_and_total_deadlines_bound_response_streams() {
    for total in [false, true] {
        let mut reply = Reply::body("first");
        reply.chunks = vec![Bytes::from_static(b"data"); 100];
        reply.delay = if total {
            Duration::from_millis(10)
        } else {
            Duration::from_secs(5)
        };
        let origin = Origin::spawn(reply).await;
        let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
        let limits = if total {
            Limits {
                total_timeout: Duration::from_millis(150),
                ..Limits::default()
            }
        } else {
            Limits {
                idle_timeout: Duration::from_millis(150),
                ..Limits::default()
            }
        };
        let response = transport
            .execute(
                Endpoint::new(&origin.origin(), origin.address).unwrap(),
                request(&origin.origin()),
                limits,
                Cancellation::default(),
            )
            .await
            .unwrap();
        let collected =
            tokio::time::timeout(Duration::from_secs(2), response.into_body().collect())
                .await
                .expect("deadline did not abort body");
        assert!(matches!(collected, Err(error) if error.code == ErrorCode::OutcomeUnknown));
        assert_eq!(origin.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn resolver_returns_complete_localhost_candidates_without_dialing() {
    let resolver = SystemResolver {
        timeout: Duration::from_secs(2),
    };
    let addresses = resolver.resolve("localhost", 8443).await.unwrap();
    assert!(!addresses.is_empty());
    assert!(
        addresses
            .iter()
            .all(|address| address.ip().is_loopback() && address.port() == 8443)
    );
    assert!(resolver.resolve("localhost", 0).await.is_err());
    assert!(resolver.resolve("https://localhost", 8443).await.is_err());
}

#[tokio::test]
async fn verified_https_streams_without_redirects_or_retries() {
    let mut reply = Reply::body(Bytes::from_static(b"first"));
    reply.status = 302;
    reply.headers = vec![("location".into(), "https://forbidden.test".into())];
    reply.chunks.push(Bytes::from_static(b"second"));
    let origin = Origin::spawn(reply).await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    let endpoint = Endpoint::new(&origin.origin(), origin.address).unwrap();
    let response = transport
        .execute(
            endpoint,
            request(&origin.origin()),
            Limits::default(),
            Cancellation::default(),
        )
        .await
        .expect("verified request failed");
    assert_eq!(response.status(), 302);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "firstsecond"
    );
    let requests = origin.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target, "/messages");
    assert_eq!(requests[0].body, "synthetic-body");
    assert_eq!(requests[0].headers["authorization"], "Bearer synthetic-key");
}

#[tokio::test]
async fn certificate_and_authority_failures_send_no_application_request() {
    let origin = Origin::spawn(Reply::body("ok")).await;
    let untrusted = HttpsTransport::new([]).unwrap();
    let result = untrusted
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            request(&origin.origin()),
            Limits::default(),
            Cancellation::default(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::UpstreamUnavailable));
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    let result = transport
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            request("https://other.test"),
            Limits::default(),
            Cancellation::default(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::RequestInvalid));
    assert!(origin.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_disconnect_after_reception_is_uncertain_and_never_repeated() {
    let mut reply = Reply::body("");
    reply.disconnect = true;
    let origin = Origin::spawn(reply).await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    let result = transport
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            request(&origin.origin()),
            Limits::default(),
            Cancellation::default(),
        )
        .await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::OutcomeUnknown));
    assert_eq!(origin.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn response_limits_and_cancellation_abort_streams() {
    let origin = Origin::spawn(Reply::body("too large")).await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    let limits = Limits {
        max_response_bytes: 2,
        ..Limits::default()
    };
    let response = transport
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            request(&origin.origin()),
            limits,
            Cancellation::default(),
        )
        .await
        .unwrap();
    assert!(response.into_body().collect().await.is_err());
    let mut reply = Reply::body("delayed");
    reply.delay = Duration::from_secs(5);
    let origin = Origin::spawn(reply).await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    let cancellation = Cancellation::default();
    let response = transport
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            request(&origin.origin()),
            Limits::default(),
            cancellation.clone(),
        )
        .await
        .unwrap();
    cancellation.cancel();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), response.into_body().collect())
            .await
            .unwrap()
            .is_err()
    );
}
