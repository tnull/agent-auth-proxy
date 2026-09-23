use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};

async fn request(path: &std::path::Path, method: &str, body: Value) -> (http::StatusCode, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let socket = tokio::net::UnixStream::connect(path).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
                .await
                .unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                http::Request::builder()
                    .method("POST")
                    .uri(method)
                    .header("host", "aap.local")
                    .header("content-type", "application/json")
                    .header("connection", "close")
                    .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        driver.await.unwrap().unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    })
    .await
    .expect("scoped observer response stalled")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_observer_rejects_read_and_ack_before_cleanup_finishes() {
    let fixture = Fixture::new().await;
    let session = fixture
        .control
        .create(CreateSession {
            resources: vec![],
            items: None,
            lifetime_seconds: 60,
            require_approval: false,
            require_observation: false,
        })
        .unwrap();
    let observer = fixture
        .control
        .create_observation(CreateObservation {
            scope: aap_observe::Scope {
                sessions: vec![session.session_id.clone()],
                views: vec![aap_observe::View::Upstream],
                classes: vec![aap_observe::ContentClass::Metadata],
            },
            limits: aap_observe::SubscriptionLimits {
                max_events: 16,
                max_bytes: 32768,
            },
            lifetime_seconds: 60,
        })
        .unwrap();
    let path = fixture.root.join("r").join(observer.observation_socket);
    let (status, batch) = request(&path, "/aap/observe/v1/read", json!({"limit":16})).await;
    assert!(status.is_success());
    let cursor = batch["cursor"].clone();
    assert!(
        request(&path, "/aap/observe/v1/ack", cursor.clone())
            .await
            .0
            .is_success()
    );
    fixture
        .control
        .recorder
        .record(
            aap_observe::Event {
                session_id: session.session_id,
                request_id: None,
                parent_request_id: None,
                flow_id: aap_types::ids::random_id(16).unwrap(),
                stream_id: "inbound.upstream".into(),
                sequence: 0,
                protocol: aap_observe::Protocol::Http1,
                inspection: aap_observe::Inspection::Parsed,
                redaction: aap_observe::Redaction::Transformed,
                policy_version: 1,
                direction: aap_observe::Direction::Inbound,
                view: aap_observe::View::Upstream,
                data: aap_observe::Data::ResponseStart {
                    status: 200,
                    headers: vec![],
                },
            },
            false,
        )
        .unwrap();
    let (status, batch) = request(&path, "/aap/observe/v1/read", json!({"limit":16})).await;
    assert!(status.is_success());
    assert_eq!(batch["deliveries"].as_array().unwrap().len(), 1);
    let cursor = batch["cursor"].clone();
    fixture.write(2, 2);
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    *fixture.control.cleanup_hook.lock().unwrap() = Some(Box::new(move || {
        entered.send(()).unwrap();
        // Dropping the sender on a test failure also releases the worker.
        let _ = released.recv();
        Ok(())
    }));
    let control = fixture.control.clone();
    let reload = tokio::spawn(async move { control.reload().await });
    waiting.await.unwrap();
    let read = request(&path, "/aap/observe/v1/read", json!({"limit":16})).await;
    let ack = request(&path, "/aap/observe/v1/ack", cursor).await;
    release.send(()).unwrap();
    reload.await.unwrap().unwrap();
    assert_eq!(
        [read.0, ack.0],
        [http::StatusCode::SERVICE_UNAVAILABLE; 2],
        "retired observer kept read/ack authority while cleanup was pending"
    );
    for (_, body) in [read, ack] {
        assert_eq!(body["code"], "observation_unavailable");
    }
}
