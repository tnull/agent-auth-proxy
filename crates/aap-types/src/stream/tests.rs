use super::*;
use crate::OperationState;
use serde_json::{Value, json};

fn operation() -> Open {
    Open {
        request_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        resource: "echo-fixture".into(),
    }
}

fn opened() -> Opened {
    let operation = operation();
    Opened {
        request_id: operation.request_id,
        resource: operation.resource,
        max_data_bytes: MAX_DATA_BYTES as u32,
        send_limit: MAX_DIRECTION_BYTES,
        receive_limit: MAX_DIRECTION_BYTES,
        idle_timeout_ms: MAX_IDLE_MS,
        remaining_lifetime_ms: MAX_LIFETIME_MS,
        inspection: Inspection::PlaintextBytes,
        observation: Observation::Required,
    }
}

fn terminal(state: OperationState, cause: Cause, sent: u64, received: u64) -> Frame {
    Frame::Terminal(Terminal {
        operation: OperationStatus {
            request_id: operation().request_id,
            state,
            status: None,
        },
        cause,
        sent_bytes: sent,
        received_bytes: received,
    })
}

fn wire(frame: &Frame) -> Vec<u8> {
    let encoded = frame.encode().unwrap();
    [encoded.header.as_slice(), &encoded.payload].concat()
}

fn decode_json(kind: Kind, value: &Value) -> Result<Frame> {
    decode_bytes(kind, &serde_json::to_vec(value).unwrap())
}

fn decode_bytes(kind: Kind, bytes: &[u8]) -> Result<Frame> {
    let mut raw = [0; 5];
    raw[0] = kind as u8;
    raw[1..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    Frame::decode(Header::parse(raw)?, Bytes::copy_from_slice(bytes))
}

#[test]
fn open_is_strict_canonical_bounded_and_cannot_supply_authority() {
    let bytes = serde_json::to_vec(&operation()).unwrap();
    assert_eq!(Open::decode(&bytes).unwrap(), operation());
    for value in [
        json!({"request_id":"short","resource":"echo-fixture"}),
        json!({"request_id":"AAAAAAAAAAAAAAAAAAAAAB","resource":"echo-fixture"}),
        json!({"request_id":operation().request_id,"resource":"../echo"}),
        json!({"request_id":operation().request_id,"resource":"_echo"}),
        json!({"request_id":operation().request_id,"resource":"a".repeat(65)}),
        json!({"request_id":operation().request_id,"resource":"echo","session_id":"other"}),
        json!({"request_id":operation().request_id,"resource":"echo","destination":"host:443"}),
        json!({"request_id":operation().request_id,"resource":null}),
    ] {
        assert!(Open::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(
        Open::decode(
            br#"{"request_id":"AAAAAAAAAAAAAAAAAAAAAA","resource":"echo","\u0072esource":"other"}"#
        )
        .is_err()
    );
    assert!(Open::decode(&[bytes.as_slice(), b"{}"].concat()).is_err());
    assert_eq!(
        Open::decode(&vec![b' '; MAX_CONTROL_BYTES + 1])
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    // Preflight nesting and structural expansion before allocating a JSON tree.
    for hostile in [
        format!("{}0{}", "[".repeat(9), "]".repeat(9)),
        format!("[{}0]", "0,".repeat(128)),
    ] {
        assert_eq!(
            Open::decode(hostile.as_bytes()).unwrap_err().code,
            ErrorCode::LimitExceeded
        );
    }
}

#[test]
fn frame_bytes_are_exact_and_lengths_are_checked_before_payload() {
    let data = Frame::Data(Bytes::from_static(&[255, 0, 10]));
    assert_eq!(wire(&data), [3, 0, 0, 0, 3, 255, 0, 10]);
    assert_eq!(wire(&Frame::SendEnd), [4, 0, 0, 0, 0]);
    assert!(
        matches!(decode_bytes(Kind::Data, &[255, 0, 10]).unwrap(), Frame::Data(bytes) if bytes.as_ref() == [255, 0, 10])
    );
    for bytes in [
        [0, 0, 0, 0, 0],
        [6, 0, 0, 0, 0],
        [3, 0, 0, 0, 0],
        [4, 0, 0, 0, 1],
        [1, 0, 0, 0, 0],
        [2, 0, 0, 0, 0],
        [5, 0, 0, 0, 0],
    ] {
        assert!(
            Header::parse(bytes).is_err(),
            "invalid header accepted: {bytes:?}"
        );
    }
    for kind in [Kind::Pending, Kind::Opened, Kind::Data, Kind::Terminal] {
        let max = if kind == Kind::Data {
            MAX_DATA_BYTES
        } else {
            MAX_CONTROL_BYTES
        };
        let mut raw = [kind as u8, 0, 0, 0, 0];
        raw[1..].copy_from_slice(&((max + 1) as u32).to_be_bytes());
        assert_eq!(
            Header::parse(raw).unwrap_err().code,
            ErrorCode::LimitExceeded
        );
        raw[1..].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            Header::parse(raw).unwrap_err().code,
            ErrorCode::LimitExceeded
        );
    }
    assert!(Frame::Data(Bytes::new()).encode().is_err());
    assert!(
        Frame::Data(Bytes::from(vec![0; MAX_DATA_BYTES + 1]))
            .encode()
            .is_err()
    );
    let header = Header::parse([3, 0, 0, 0, 3]).unwrap();
    for len in [0, 2, 4] {
        assert!(Frame::decode(header, Bytes::from(vec![0; len])).is_err());
    }
}

#[test]
fn controls_require_exact_fields_integer_limits_and_terminal_status() {
    let open = serde_json::to_value(opened()).unwrap();
    assert!(decode_json(Kind::Opened, &open).is_ok());
    for key in [
        "max_data_bytes",
        "send_limit",
        "receive_limit",
        "idle_timeout_ms",
        "remaining_lifetime_ms",
    ] {
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("1"),
            json!(u64::MAX),
            Value::Null,
        ] {
            let mut changed = open.clone();
            changed[key] = bad;
            assert!(
                decode_json(Kind::Opened, &changed).is_err(),
                "accepted {key}: {changed}"
            );
        }
        let mut changed = open.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(decode_json(Kind::Opened, &changed).is_err());
    }
    for (key, bad) in [
        ("inspection", "parsed"),
        ("observation", "disabled"),
        ("request_id", "foreign"),
        ("resource", "bad/resource"),
    ] {
        let mut changed = open.clone();
        changed[key] = json!(bad);
        assert!(decode_json(Kind::Opened, &changed).is_err());
    }
    let mut unknown = open.clone();
    unknown["store_ref"] = json!("private");
    assert!(decode_json(Kind::Opened, &unknown).is_err());
    assert!(
        decode_bytes(
            Kind::Pending,
            br#"{"request_id":"AAAAAAAAAAAAAAAAAAAAAA","expires_in_ms":1,"expires_in_ms":2}"#
        )
        .is_err()
    );
    for remaining in [0, MAX_APPROVAL_MS + 1] {
        assert!(
            Frame::Pending(Pending {
                request_id: operation().request_id,
                expires_in_ms: remaining
            })
            .encode()
            .is_err()
        );
    }
    let frame = terminal(OperationState::OutcomeUnknown, Cause::Cancelled, 1, 2);
    let encoded = frame.encode().unwrap();
    let good: Value = crate::json::decode(&encoded.payload).unwrap();
    assert!(decode_json(Kind::Terminal, &good).is_ok());
    let mut missing = good.clone();
    missing["operation"]
        .as_object_mut()
        .unwrap()
        .remove("status");
    assert!(
        decode_json(Kind::Terminal, &missing).is_err(),
        "TCP status:null is required"
    );
    for (key, bad) in [
        ("status", json!(200)),
        ("state", json!("dispatching")),
        ("secret", json!("leak")),
    ] {
        let mut changed = good.clone();
        changed["operation"][key] = bad;
        assert!(decode_json(Kind::Terminal, &changed).is_err());
    }
    for (key, bad) in [
        ("cause", json!("retry")),
        ("sent_bytes", json!(-1)),
        ("received_bytes", json!(MAX_DIRECTION_BYTES + 1)),
    ] {
        let mut changed = good.clone();
        changed[key] = bad;
        assert!(decode_json(Kind::Terminal, &changed).is_err());
    }
    assert!(
        terminal(OperationState::Completed, Cause::Timeout, 0, 0)
            .encode()
            .is_err()
    );
    assert!(
        terminal(OperationState::OutcomeUnknown, Cause::OrderlyEnd, 0, 0)
            .encode()
            .is_err()
    );
}

#[test]
fn directional_state_binds_opening_and_preserves_opposite_half_close() {
    for first in [Sender::Agent, Sender::Daemon] {
        let mut sequence = Sequence::new(operation()).unwrap();
        let pending = Frame::Pending(Pending {
            request_id: operation().request_id,
            expires_in_ms: 1,
        });
        let data = Frame::Data(Bytes::from_static(b"abc"));
        assert!(sequence.accept(Sender::Agent, &pending).is_err());
        assert!(sequence.accept(Sender::Agent, &data).is_err());
        sequence.accept(Sender::Daemon, &pending).unwrap();
        assert!(sequence.accept(Sender::Daemon, &pending).is_err());
        let mut foreign = opened();
        foreign.resource = "other".into();
        assert!(
            sequence
                .accept(Sender::Daemon, &Frame::Opened(foreign))
                .is_err()
        );
        let opening = Frame::Opened(opened());
        assert!(sequence.accept(Sender::Agent, &opening).is_err());
        sequence.accept(Sender::Daemon, &opening).unwrap();
        assert!(sequence.accept(Sender::Daemon, &opening).is_err());
        assert!(sequence.accept(Sender::Daemon, &pending).is_err());
        sequence.accept(first, &Frame::SendEnd).unwrap();
        assert!(sequence.ended(first));
        assert!(sequence.accept(first, &data).is_err());
        assert!(sequence.accept(first, &Frame::SendEnd).is_err());
        let other = if first == Sender::Agent {
            Sender::Daemon
        } else {
            Sender::Agent
        };
        sequence.accept(other, &data).unwrap();
        let (sent, received) = if other == Sender::Agent {
            (3, 0)
        } else {
            (0, 3)
        };
        let done = terminal(OperationState::Completed, Cause::OrderlyEnd, sent, received);
        assert!(sequence.accept(Sender::Daemon, &done).is_err());
        sequence.accept(other, &Frame::SendEnd).unwrap();
        assert!(sequence.accept(Sender::Agent, &done).is_err());
        sequence.accept(Sender::Daemon, &done).unwrap();
        assert!(sequence.is_terminal());
        assert!(sequence.accept(Sender::Daemon, &done).is_err());
        assert!(sequence.accept(Sender::Agent, &data).is_err());
    }
}

#[test]
fn narrowed_bytes_and_frame_counts_cannot_be_reset_by_chunking() {
    let mut sequence = Sequence::new(operation()).unwrap();
    let mut opening = opened();
    opening.max_data_bytes = 3;
    opening.send_limit = 4;
    opening.receive_limit = 5;
    sequence
        .accept(Sender::Daemon, &Frame::Opened(opening))
        .unwrap();
    assert_eq!(
        sequence
            .check_header(Sender::Agent, Header::parse([3, 0, 0, 0, 4]).unwrap())
            .unwrap_err()
            .code,
        ErrorCode::LimitExceeded
    );
    sequence
        .accept(Sender::Agent, &Frame::Data(Bytes::from_static(b"123")))
        .unwrap();
    assert!(
        sequence
            .check_header(Sender::Agent, Header::parse([3, 0, 0, 0, 2]).unwrap())
            .is_err()
    );
    sequence
        .accept(Sender::Agent, &Frame::Data(Bytes::from_static(b"4")))
        .unwrap();
    assert!(
        sequence
            .accept(Sender::Agent, &Frame::Data(Bytes::from_static(b"5")))
            .is_err()
    );
    sequence
        .accept(Sender::Daemon, &Frame::Data(Bytes::from_static(b"123")))
        .unwrap();
    sequence
        .accept(Sender::Daemon, &Frame::Data(Bytes::from_static(b"45")))
        .unwrap();
    assert!(
        sequence
            .accept(Sender::Daemon, &Frame::Data(Bytes::from_static(b"6")))
            .is_err()
    );

    let mut sequence = Sequence::new(operation()).unwrap();
    sequence
        .accept(Sender::Daemon, &Frame::Opened(opened()))
        .unwrap();
    let small = Frame::Data(Bytes::from_static(b"x"));
    for _ in 0..MAX_DATA_FRAMES {
        sequence.accept(Sender::Agent, &small).unwrap();
    }
    assert_eq!(
        sequence.accept(Sender::Agent, &small).unwrap_err().code,
        ErrorCode::LimitExceeded
    );
    sequence.accept(Sender::Daemon, &small).unwrap();
    sequence.accept(Sender::Agent, &Frame::SendEnd).unwrap();
}

#[test]
fn terminal_reports_uncertainty_without_inventing_delivery_or_completion() {
    let mut before = Sequence::new(operation()).unwrap();
    assert!(
        before
            .accept(
                Sender::Daemon,
                &terminal(OperationState::Completed, Cause::OrderlyEnd, 0, 0)
            )
            .is_err()
    );
    before
        .accept(
            Sender::Daemon,
            &terminal(OperationState::Denied, Cause::ApprovalDenied, 0, 0),
        )
        .unwrap();
    assert!(before.is_terminal());
    // A connection attempt can become uncertain even if OPENED was never sent.
    let mut dialing = Sequence::new(operation()).unwrap();
    dialing
        .accept(
            Sender::Daemon,
            &terminal(
                OperationState::OutcomeUnknown,
                Cause::UpstreamUnavailable,
                0,
                0,
            ),
        )
        .unwrap();
    let mut live = Sequence::new(operation()).unwrap();
    live.accept(Sender::Daemon, &Frame::Opened(opened()))
        .unwrap();
    live.accept(Sender::Agent, &Frame::Data(Bytes::from_static(b"abc")))
        .unwrap();
    assert!(
        live.accept(
            Sender::Daemon,
            &terminal(OperationState::Cancelled, Cause::Cancelled, 0, 0)
        )
        .is_err()
    );
    assert!(
        live.accept(
            Sender::Daemon,
            &terminal(OperationState::OutcomeUnknown, Cause::Timeout, 4, 0)
        )
        .is_err()
    );
    live.accept(
        Sender::Daemon,
        &terminal(OperationState::OutcomeUnknown, Cause::Cancelled, 2, 0),
    )
    .unwrap();
    assert!(live.is_terminal());
}

#[test]
fn decoder_handles_every_split_coalescing_binary_and_explicit_eof() {
    let frames = [
        Frame::Opened(opened()),
        Frame::Data(Bytes::from_static(&[255, 0, 10])),
        Frame::SendEnd,
        terminal(OperationState::OutcomeUnknown, Cause::Timeout, 0, 3),
    ];
    let bytes: Vec<u8> = frames.iter().flat_map(wire).collect();
    for split in 0..=bytes.len() {
        let mut decoder = Decoder::default();
        let mut sequence = Sequence::new(operation()).unwrap();
        let mut count = 0;
        for part in [&bytes[..split], &bytes[split..]] {
            let mut input = part;
            while !input.is_empty() {
                if let Some(frame) = decoder
                    .next(&mut input, &mut sequence, Sender::Daemon)
                    .unwrap()
                {
                    if count == 1 {
                        assert!(
                            matches!(frame, Frame::Data(data) if data.as_ref() == [255, 0, 10])
                        );
                    }
                    count += 1;
                }
            }
        }
        assert_eq!(count, frames.len());
        decoder.finish(&sequence).unwrap();
    }
    // Incomplete header, payload, or terminal is never successful EOF.
    for end in 0..bytes.len() {
        let mut decoder = Decoder::default();
        let mut sequence = Sequence::new(operation()).unwrap();
        let mut input = &bytes[..end];
        while !input.is_empty() {
            decoder
                .next(&mut input, &mut sequence, Sender::Daemon)
                .unwrap();
        }
        assert_eq!(
            decoder.finish(&sequence).unwrap_err().code,
            ErrorCode::ResultUnavailable
        );
    }
}

#[test]
fn decoder_rejects_before_consuming_payload_and_stays_failed() {
    let mut sequence = Sequence::new(operation()).unwrap();
    sequence
        .accept(Sender::Daemon, &Frame::Opened(opened()))
        .unwrap();
    for header in [
        [3, 0, 0, 128, 1],
        [7, 0, 0, 0, 1],
        [4, 0, 0, 0, 1],
        [1, 0, 0, 0, 1],
    ] {
        let mut decoder = Decoder::default();
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(b"unread");
        let mut input = bytes.as_slice();
        assert!(
            decoder
                .next(&mut input, &mut sequence, Sender::Agent)
                .is_err()
        );
        assert_eq!(input, b"unread", "invalid header consumed its payload");
        assert!(
            decoder
                .next(&mut input, &mut sequence, Sender::Agent)
                .is_err()
        );
        assert_eq!(input, b"unread");
        assert!(decoder.finish(&sequence).is_err());
    }
    let mut decoder = Decoder::default();
    let mut sequence = Sequence::new(operation()).unwrap();
    let mut early: &[u8] = &[3, 0, 0, 0, 1, 255];
    assert!(
        decoder
            .next(&mut early, &mut sequence, Sender::Agent)
            .is_err()
    );
    assert_eq!(
        early,
        &[3, 0, 0, 0, 1, 255],
        "early input must be rejected immediately"
    );
}
