use super::{boundary::Boundary, *};
use aap_observe::{Data, Protocol, View};
use rustls::pki_types::CertificateDer;

const PRIVATE: &[&str] = &[
    "synthetic-daemon-key",
    "synthetic-second-key",
    "private-website-user",
    "private-website-password",
    "private-website-cookie",
    "private-pre",
    "private-site-csrf",
    "private-daemon-mcp",
    "private-server-ping",
];

pub(super) fn action(
    fixture: &Fixture,
    root: &CertificateDer<'_>,
    method: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Value {
    let authority = format!("fixture.test:{}", fixture.origin.address.port());
    json!({"kind":"connect","request":{
        "authority":authority,"server_name":"fixture.test","root_der":root.as_ref(),
        "method":method,"path":path,"host":authority,
        "headers":[["content-type",content_type]],"body":body
    }})
}

pub(super) fn response(value: &Value, status: u16) -> Vec<u8> {
    assert_eq!(value["phase"], "http");
    assert_eq!(value["tls_verified"], true);
    assert_eq!(value["status"], status);
    for field in ["headers", "trailers"] {
        for header in value[field].as_array().unwrap() {
            assert_ne!(header[0], "set-cookie");
            assert_ne!(header[0], "mcp-session-id");
            for secret in PRIVATE {
                assert!(!header.to_string().contains(secret));
            }
        }
    }
    let bytes: Vec<u8> = serde_json::from_value(value["body"].clone()).unwrap();
    for secret in PRIVATE {
        assert!(!String::from_utf8_lossy(&bytes).contains(secret));
    }
    bytes
}

pub(super) async fn connections(fixture: &Fixture, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.origin.accepted_connections() < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fixture did not record the expected TCP receipts");
    assert_eq!(fixture.origin.accepted_connections(), expected);
}

pub(super) async fn observations(
    boundary: &Boundary,
    expected: usize,
    gap: bool,
) -> Vec<aap_observe::Record> {
    let (records, gaps) = boundary.observations().await;
    assert_eq!(!gaps.is_empty(), gap, "unexpected observation loss state");
    assert!(records.iter().any(|record| {
        record.event.protocol == Protocol::Tls
            && matches!(record.event.data, Data::ConnectAdmission { .. })
    }));
    let mut complete = HashMap::<String, (usize, usize)>::new();
    for record in &records {
        let wire = serde_json::to_string(record).unwrap();
        let content = match &record.event.data {
            Data::ContentChunk { body_base64, .. } => STANDARD.decode(body_base64).unwrap(),
            _ => vec![],
        };
        for private in PRIVATE
            .iter()
            .copied()
            .chain(["aap_pw1_", "aap_un1_", "aap_cs1_"])
        {
            assert!(!wire.contains(private));
            assert!(!String::from_utf8_lossy(&content).contains(private));
        }
        if matches!(record.event.data, Data::FlowClose { complete: true, .. }) {
            let counts = complete
                .entry(record.event.request_id.clone().unwrap())
                .or_default();
            match record.event.view {
                View::Agent => counts.0 += 1,
                View::Upstream => counts.1 += 1,
            }
        }
    }
    assert_eq!(complete.len(), expected);
    assert!(complete.values().all(|views| *views == (1, 1)));
    records
}

pub(super) fn endings(records: &[aap_observe::Record], id: &str, complete: bool) {
    for view in [View::Agent, View::Upstream] {
        let endings: Vec<_> = records
            .iter()
            .filter(|record| {
                record.event.request_id.as_deref() == Some(id)
                    && record.event.view == view
                    && matches!(record.event.data, Data::FlowClose { .. })
            })
            .collect();
        assert_eq!(
            endings.len(),
            1,
            "each view needs exactly one logical ending"
        );
        assert!(
            matches!(endings[0].event.data, Data::FlowClose { complete: actual, .. } if actual == complete)
        );
    }
}

#[tokio::test]
#[ignore = "requires the explicit Linux confinement setup in docs/confinement.md"]
async fn confined_connect_verifies_tls_and_never_bypasses_admission() {
    let _exclusive = LAUNCH_TEST_LOCK.lock().await;
    let mut fixture = Fixture::new().await;
    let root = super::super::interception::enroll_ca(&mut fixture).await;
    let (mut daemon, ready) = fixture.start().await;
    let boundary = Boundary::new(
        &fixture,
        &daemon,
        &ready,
        json!({"resources":["provider"],"lifetime_seconds":120}),
        &[fixture.origin.address],
    )
    .await;
    // Parent and descendant positive controls both reach the actual origin's
    // TCP listener but send only probe bytes, not a TLS or HTTP request.
    connections(&fixture, 2).await;
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    let request = action(
        &fixture,
        &root,
        "POST",
        "/v1/chat/completions",
        "application/json",
        STANDARD.decode(fixture.request().body_base64).unwrap(),
    );
    let mut first = boundary.spawn(0).await;
    assert_eq!(
        response(&boundary.action(&mut first, 0, request.clone()).await, 200),
        b"data: [redacted]\n\n"
    );
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert_eq!(
        fixture.origin.requests.lock().unwrap()[0].headers["authorization"],
        "Bearer synthetic-daemon-key"
    );
    connections(&fixture, 3).await;

    let mut wrong = request.clone();
    wrong["request"]["host"] = json!("other.test");
    response(&boundary.action(&mut first, 0, wrong).await, 403);
    let mut wrong = request.clone();
    wrong["request"]["authority"] = json!("other.test:443");
    let refused = boundary.action(&mut first, 0, wrong).await;
    assert_eq!(refused["phase"], "connect");
    assert_eq!(refused["status"], 403);
    assert_eq!(refused["tls_verified"], false);
    for wrong in [
        {
            let mut wrong = request.clone();
            wrong["request"]["server_name"] = json!("other.test");
            wrong
        },
        {
            let mut wrong = request.clone();
            // The origin certificate is not the interception trust root.
            wrong["request"]["root_der"] = json!(fixture.origin.certificate.as_ref());
            wrong
        },
    ] {
        let refused = boundary.action(&mut first, 0, wrong).await;
        assert_eq!(refused["phase"], "tls");
        assert_eq!(refused["error"], "tls_rejected");
        assert_eq!(refused["tls_verified"], false);
    }
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    connections(&fixture, 3).await;

    let mut second = boundary.spawn(1).await;
    response(&boundary.action(&mut second, 1, request.clone()).await, 200);
    let collector = boundary.tiny_collector(0).await;
    let denied = boundary.action(&mut first, 0, request.clone()).await;
    // CONNECT rechecks admission after resolving its CA identity. Its second
    // metadata event exceeds this collector's capacity before TLS can start.
    assert_eq!(denied["phase"], "connect");
    assert_eq!(denied["status"], 503);
    assert_eq!(denied["tls_verified"], false);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    connections(&fixture, 4).await;
    boundary.remove_collector(collector).await;
    response(&boundary.action(&mut first, 0, request.clone()).await, 200);
    let mut approval = boundary.approval_process(&fixture, &["provider"]).await;
    let denied = boundary.action(&mut approval, 0, request).await;
    let body = response(&denied, 503);
    assert!(String::from_utf8_lossy(&body).contains("interaction_unavailable"));
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    connections(&fixture, 5).await;
    observations(&boundary, 3, true).await;
    boundary.assert_no_bypass();
    first.finish().await;
    second.finish().await;
    approval.finish().await;
    stop(&mut daemon).await;
}
