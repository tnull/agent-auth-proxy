use super::*;
use aap_observe::{Data, Direction, Record, View};
use base64::engine::general_purpose::STANDARD;

#[tokio::test]
async fn abandoned_response_reports_incomplete_views_not_policy_denial() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    let input = fixture.request();
    let id = input.request_id.clone();
    drop(session.execute(input).await.unwrap());
    let records: Vec<_> = fixture
        .recorder
        .read(None, 256)
        .unwrap()
        .records
        .into_iter()
        .filter(|record| record.event.request_id.as_deref() == Some(&id))
        .collect();
    for view in [View::Agent, View::Upstream] {
        assert!(records.iter().any(|record| record.event.view == view
            && matches!(
                record.event.data,
                Data::FlowClose {
                    complete: false,
                    reason: Some(ErrorCode::OutcomeUnknown),
                    ..
                }
            )));
        assert!(records.iter().any(|record| record.event.view == view
            && record.event.direction == Direction::Inbound
            && matches!(
                record.event.data,
                Data::ContentEnd {
                    complete: false,
                    bytes: 0,
                    reason: Some(ErrorCode::OutcomeUnknown)
                }
            )));
    }
    assert!(
        !records.iter().any(|record| matches!(
            record.event.data,
            Data::PolicyDecision {
                decision: aap_observe::Decision::Deny,
                ..
            }
        )),
        "transport abandonment must not invent a policy denial"
    );
    assert_eq!(
        session.request_status(id).await.unwrap().state,
        OperationState::OutcomeUnknown
    );
}

#[test]
fn observation_headers_withhold_unknown_names_and_nonconstant_values() {
    let safe = super::super::observation::request_headers(&[
        ("Private-Password".into(), "private-cookie".into()),
        (
            "Content-Type".into(),
            "application/json;private-password=private-cookie".into(),
        ),
        ("Content-Length".into(), "100".into()),
        ("Authorization".into(), "Bearer private-password".into()),
        (
            "Set-Cookie".into(),
            "private-password=private-cookie".into(),
        ),
        ("Anthropic-Version".into(), "private-password".into()),
    ]);
    assert_eq!(
        safe,
        [
            ("[withheld]".into(), "[withheld]".into()),
            ("content-type".into(), "application/json".into()),
            ("authorization".into(), "[redacted]".into()),
            ("set-cookie".into(), "[redacted]".into()),
            ("anthropic-version".into(), "[redacted]".into()),
        ]
    );
}

pub(super) fn content(records: &[Record], direction: Direction, view: View) -> Vec<u8> {
    let selected: Vec<_> = records
        .iter()
        .filter(|record| record.event.direction == direction && record.event.view == view)
        .collect();
    assert!(
        !selected.is_empty(),
        "missing directional view: {direction:?} {view:?}"
    );
    let mut bytes = Vec::new();
    let mut ended = false;
    for (sequence, record) in selected.iter().enumerate() {
        assert_eq!(record.event.sequence, sequence as u64);
        match &record.event.data {
            Data::ContentChunk {
                offset,
                body_base64,
                ..
            } => {
                assert!(!ended);
                assert_eq!(*offset, bytes.len() as u64);
                bytes.extend(STANDARD.decode(body_base64).unwrap());
            }
            Data::ContentEnd {
                complete,
                bytes: count,
                reason,
            } => {
                assert!(!ended);
                assert!(*complete);
                assert!(reason.is_none());
                assert_eq!(*count, bytes.len() as u64);
                ended = true;
            }
            _ => {}
        }
    }
    assert!(ended, "view had no explicit content ending");
    bytes
}

#[tokio::test]
async fn provider_observation_has_correlated_sanitized_views_and_lifecycle() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let session = broker.create_session(options()).unwrap();
    let input = fixture.request();
    let original = STANDARD.decode(&input.body_base64).unwrap();
    let id = input.request_id.clone();
    let output = session
        .execute(input)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let records: Vec<_> = fixture
        .recorder
        .read(None, 256)
        .unwrap()
        .records
        .into_iter()
        .filter(|record| record.event.request_id.as_deref() == Some(&id))
        .collect();
    assert!(!records.is_empty());
    let flow = records[0].event.flow_id.clone();
    assert!(
        records
            .iter()
            .all(|record| record.event.flow_id == flow && record.event.session_id == session.id())
    );
    for view in [View::Agent, View::Upstream] {
        assert_eq!(content(&records, Direction::Outbound, view), original);
        assert_eq!(content(&records, Direction::Inbound, view), output);
        let value = serde_json::to_value(
            records
                .iter()
                .filter(|record| record.event.view == view)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let events = value.as_array().unwrap();
        assert!(
            events
                .iter()
                .any(|record| record["event"]["data"]["event_type"] == "flow_open")
        );
        assert!(events.iter().any(
            |record| record["event"]["data"]["event_type"] == "flow_close"
                && record["event"]["data"]["complete"] == true
        ));
        assert!(
            events.iter().any(
                |record| record["event"]["data"]["event_type"] == "policy_decision"
                    && record["event"]["data"]["decision"] == "allow"
            )
        );
    }
    let outbound = records
        .iter()
        .find(|record| {
            record.event.view == View::Upstream
                && matches!(record.event.data, Data::RequestStart { .. })
        })
        .unwrap();
    let headers = serde_json::to_value(&outbound.event.data).unwrap();
    assert!(
        headers["headers"]
            .as_array()
            .expect("missing structured headers")
            .iter()
            .any(|header| header == &serde_json::json!(["authorization", "[redacted]"]))
    );
    let json = serde_json::to_string(&records).unwrap();
    for secret in ["synthetic-api-key", "private-reference", "never-visible"] {
        assert!(!json.contains(secret));
    }
}
