//! Trusted bounded recording. Payloads must be sanitized by their owning adapter.
use aap_types::{ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

mod flow;
pub use flow::{Emission, Flow, FlowContext, Inspection, Protocol, Redaction};

#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub session_id: String,
    pub request_id: Option<String>,
    pub parent_request_id: Option<String>,
    pub flow_id: String,
    pub stream_id: String,
    pub sequence: u64,
    pub protocol: Protocol,
    pub inspection: Inspection,
    pub redaction: Redaction,
    pub policy_version: u64,
    pub direction: Direction,
    pub view: View,
    pub data: Data,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Outbound,
    Inbound,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum View {
    Agent,
    Upstream,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum Data {
    /// Logical flow allocation, not evidence that an upstream socket connected.
    FlowOpen {},
    FlowClose {
        complete: bool,
        outbound_bytes: u64,
        inbound_bytes: u64,
        reason: Option<ErrorCode>,
    },
    PolicyDecision {
        decision: Decision,
        reason: Option<ErrorCode>,
    },
    ConnectAdmission {
        authority: String,
    },
    RequestStart {
        method: String,
        target: String,
        headers: Vec<(String, String)>,
    },
    ResponseStart {
        status: u16,
        headers: Vec<(String, String)>,
    },
    ContentChunk {
        offset: u64,
        body_base64: String,
        media_type: Option<String>,
        encoding: String,
    },
    ContentEnd {
        complete: bool,
        bytes: u64,
        reason: Option<ErrorCode>,
    },
    AuthTransition {
        item_id: String,
        inserted: bool,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Pending,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub schema_version: u32,
    pub daemon_epoch: String,
    pub event_id: u64,
    pub time_unix_ms: u64,
    pub event: Event,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Cursor {
    pub epoch: String,
    pub after: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Batch {
    pub records: Vec<Record>,
    pub gap: Option<Gap>,
    pub cursor: Cursor,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    pub first: u64,
    pub last: u64,
    pub previous_epoch: bool,
}

#[derive(Clone)]
pub struct Recorder {
    state: Arc<Mutex<State>>,
}
struct State {
    epoch: String,
    next: u64,
    records: VecDeque<(Record, usize, bool)>,
    bytes: usize,
    max_events: usize,
    max_bytes: usize,
    available: bool,
}
impl Recorder {
    pub fn new(epoch: String, max_events: usize, max_bytes: usize) -> Result<Self> {
        if !aap_types::ids::valid_id(&epoch, 16)
            || max_events == 0
            || max_events > 65_536
            || !(512..=64 * 1024 * 1024).contains(&max_bytes)
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                epoch,
                next: 1,
                records: VecDeque::new(),
                bytes: 0,
                max_events,
                max_bytes,
                available: true,
            })),
        })
    }
    pub fn record(&self, event: Event, required: bool) -> Result<()> {
        self.record_batch(vec![event], required)
    }
    /// Accept at most sixteen records / 256 KiB as one logical update.
    /// Failed acceptance consumes IDs, but never retains a partial update.
    pub fn record_batch(&self, events: Vec<Event>, required: bool) -> Result<()> {
        if events.is_empty() || events.len() > 16 {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let first = state.next;
        state.next = first
            .checked_add(events.len() as u64)
            .ok_or(ErrorCode::ObservationUnavailable)?;
        let unavailable = || {
            if required {
                Err(ErrorCode::ObservationUnavailable.into())
            } else {
                Ok(())
            }
        };
        if !state.available || events.len() > state.max_events {
            return unavailable();
        }
        let time_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorCode::ObservationUnavailable)?
            .as_millis()
            .try_into()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let mut additions = Vec::with_capacity(events.len());
        let mut added_bytes = 0;
        for (index, event) in events.into_iter().enumerate() {
            let size_hint = event.session_id.len()
                + event.request_id.as_ref().map_or(0, String::len)
                + event.parent_request_id.as_ref().map_or(0, String::len)
                + event.flow_id.len()
                + event.stream_id.len()
                + match &event.data {
                    Data::ConnectAdmission { authority } => authority.len(),
                    Data::ContentChunk {
                        body_base64,
                        media_type,
                        encoding,
                        ..
                    } => {
                        body_base64.len()
                            + media_type.as_ref().map_or(0, String::len)
                            + encoding.len()
                    }
                    Data::RequestStart {
                        method,
                        target,
                        headers,
                    } => {
                        method.len()
                            + target.len()
                            + headers
                                .iter()
                                .map(|(name, value)| name.len() + value.len())
                                .sum::<usize>()
                    }
                    Data::ResponseStart { headers, .. } => headers
                        .iter()
                        .map(|(name, value)| name.len() + value.len())
                        .sum(),
                    Data::AuthTransition { item_id, .. } => item_id.len(),
                    _ => 0,
                };
            if size_hint > 128 * 1024 {
                return unavailable();
            }
            let record = Record {
                schema_version: 1,
                daemon_epoch: state.epoch.clone(),
                event_id: first + index as u64,
                time_unix_ms,
                event,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| ErrorCode::ObservationUnavailable)?
                .len();
            added_bytes += bytes;
            if bytes > 128 * 1024 || added_bytes > 256 * 1024 || added_bytes > state.max_bytes {
                return unavailable();
            }
            additions.push((record, bytes, required));
        }
        let mut removed_count = 0;
        let mut removed_bytes = 0;
        while state.records.len() - removed_count + additions.len() > state.max_events
            || state.bytes - removed_bytes + added_bytes > state.max_bytes
        {
            if required {
                return unavailable();
            }
            let Some((_, bytes, protected)) = state.records.get(removed_count) else {
                return unavailable();
            };
            if *protected {
                return unavailable();
            }
            removed_bytes += bytes;
            removed_count += 1;
        }
        // Capacity is decided before mutation, including best-effort eviction.
        state.records.drain(..removed_count);
        state.bytes = state.bytes - removed_bytes + added_bytes;
        state.records.extend(additions);
        Ok(())
    }
    pub fn read(&self, cursor: Option<&Cursor>, limit: usize) -> Result<Batch> {
        self.read_bounded(cursor, limit, 64 * 1024 * 1024 + 2048)
    }
    /// Read a count- and encoded-byte-bounded page without advancing past
    /// retained records that do not fit. The budget includes the batch envelope.
    pub fn read_bounded(
        &self,
        cursor: Option<&Cursor>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Batch> {
        if limit == 0 || limit > 1024 || !(512..=64 * 1024 * 1024 + 2048).contains(&max_bytes) {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let previous_epoch = cursor.is_some_and(|cursor| cursor.epoch != state.epoch);
        let after = cursor
            .filter(|_| !previous_epoch)
            .map_or(0, |cursor| cursor.after);
        if after >= state.next {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let first = state
            .records
            .iter()
            .find(|(record, _, _)| record.event_id > after)
            .map_or(state.next, |(record, _, _)| record.event_id);
        let gap = (previous_epoch || first > after + 1).then_some(Gap {
            first: after + 1,
            last: first - 1,
            previous_epoch,
        });
        let mut records = Vec::new();
        let mut position = first;
        // The fixed envelope has a canonical 22-byte epoch and bounded numeric
        // fields. Charge commas as well as the previously serialized record.
        let mut bytes = 512;
        for (record, record_bytes, _) in &state.records {
            if record.event_id < first {
                continue;
            }
            if record.event_id != position || records.len() == limit {
                break;
            }
            if bytes + record_bytes + 1 > max_bytes {
                if records.is_empty() {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                break;
            }
            bytes += record_bytes + 1;
            records.push(record.clone());
            position += 1;
        }
        Ok(Batch {
            records,
            gap,
            cursor: Cursor {
                epoch: state.epoch.clone(),
                after: position - 1,
            },
        })
    }
    pub fn acknowledge(&self, cursor: &Cursor) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        if cursor.epoch != state.epoch || cursor.after >= state.next {
            return Err(ErrorCode::RequestInvalid.into());
        }
        while state
            .records
            .front()
            .is_some_and(|(record, _, _)| record.event_id <= cursor.after)
        {
            if let Some((_, bytes, _)) = state.records.pop_front() {
                state.bytes -= bytes;
            }
        }
        Ok(())
    }
    pub fn set_available(&self, available: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.available = available;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> Event {
        Event {
            session_id: aap_types::ids::random_id(16).unwrap(),
            request_id: Some(aap_types::ids::random_id(16).unwrap()),
            parent_request_id: None,
            flow_id: aap_types::ids::random_id(16).unwrap(),
            sequence: 0,
            protocol: Protocol::Http1,
            inspection: Inspection::Parsed,
            redaction: Redaction::Transformed,
            stream_id: "response".into(),
            policy_version: 1,
            direction: Direction::Inbound,
            view: View::Agent,
            data: Data::ResponseStart {
                status: 200,
                headers: vec![],
            },
        }
    }
    #[test]
    fn byte_bounded_pages_resume_without_losing_records() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 8, 32 * 1024).unwrap();
        for _ in 0..4 {
            let mut input = event();
            // Escaping expands this payload: budgeting raw field lengths is wrong.
            input.data = Data::RequestStart {
                method: "GET".into(),
                target: "\u{0001}".repeat(180),
                headers: vec![],
            };
            recorder.record(input, true).unwrap();
        }
        // Include the extended flow envelope without weakening the one-record
        // page assertion: size a page for exactly one serialized record.
        let budget = 512
            + serde_json::to_vec(&recorder.read(None, 1).unwrap().records[0])
                .unwrap()
                .len()
            + 1;
        let first = recorder
            .read_bounded(None, 8, budget)
            .expect("bounded page must fit one record");
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.cursor.after, 1);
        assert!(serde_json::to_vec(&first).unwrap().len() <= budget);
        let second = recorder
            .read_bounded(Some(&first.cursor), 8, budget)
            .unwrap();
        assert_eq!(second.records[0].event_id, 2);
        assert!(second.gap.is_none());
        assert!(
            matches!(recorder.read_bounded(None, 8, 512), Err(error) if error.code == ErrorCode::LimitExceeded)
        );
        assert!(
            matches!(recorder.read_bounded(None, 8, 0), Err(error) if error.code == ErrorCode::RequestInvalid)
        );
        let remaining = recorder
            .read_bounded(Some(&second.cursor), 1, budget)
            .unwrap();
        assert_eq!(remaining.records.len(), 1);
        assert_eq!(remaining.records[0].event_id, 3);
        let last = recorder
            .read_bounded(Some(&remaining.cursor), 8, budget)
            .unwrap();
        assert_eq!(last.records[0].event_id, 4);
        assert!(
            recorder
                .read_bounded(Some(&last.cursor), 8, 512)
                .unwrap()
                .records
                .is_empty()
        );
    }
    #[test]
    fn bounded_retention_exposes_gaps_and_epoch_changes() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 2, 8192)
            .expect("recorder creation failed");
        for _ in 0..3 {
            recorder.record(event(), false).unwrap();
        }
        let batch = recorder.read(None, 10).unwrap();
        assert_eq!(batch.records.len(), 2);
        assert_eq!(
            batch.gap.unwrap(),
            Gap {
                first: 1,
                last: 1,
                previous_epoch: false
            }
        );
        assert_eq!(batch.records[0].event_id, 2);
        assert_eq!(batch.records[1].event_id, 3);
        assert!(
            recorder
                .read(Some(&batch.cursor), 10)
                .unwrap()
                .records
                .is_empty()
        );
        let old = Cursor {
            epoch: aap_types::ids::random_id(16).unwrap(),
            after: 99,
        };
        assert!(
            recorder
                .read(Some(&old), 10)
                .unwrap()
                .gap
                .unwrap()
                .previous_epoch
        );
    }
    #[test]
    fn required_recording_backpressures_until_acknowledged_and_fails_offline() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 1, 8192).unwrap();
        recorder.record(event(), true).unwrap();
        assert!(recorder.record(event(), true).is_err());
        let batch = recorder.read(None, 10).unwrap();
        recorder.acknowledge(&batch.cursor).unwrap();
        recorder.record(event(), true).unwrap();
        recorder.set_available(false);
        assert!(recorder.record(event(), true).is_err());
        assert!(recorder.record(event(), false).is_ok());
    }
    #[test]
    fn best_effort_cannot_evict_unacknowledged_required_records() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 1, 8192).unwrap();
        recorder.record(event(), true).unwrap();
        recorder.record(event(), false).unwrap();
        let batch = recorder.read(None, 10).unwrap();
        assert_eq!(batch.records[0].event_id, 1, "required record was evicted");
        let next = recorder.read(Some(&batch.cursor), 10).unwrap();
        assert_eq!(
            next.gap.unwrap(),
            Gap {
                first: 2,
                last: 2,
                previous_epoch: false
            }
        );
    }

    #[test]
    fn paired_records_are_all_or_nothing_and_loss_preserves_event_identity() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 2, 8192).unwrap();
        recorder
            .record_batch(vec![event(), event()], true)
            .expect("paired records were refused");
        let batch = recorder.read(None, 10).unwrap();
        assert_eq!(batch.records.len(), 2);
        recorder
            .acknowledge(&Cursor {
                epoch: batch.cursor.epoch.clone(),
                after: 1,
            })
            .unwrap();
        assert!(recorder.record_batch(vec![event(), event()], true).is_err());
        let remaining = recorder.read(None, 10).unwrap();
        assert_eq!(remaining.records.len(), 1);
        assert_eq!(remaining.records[0].event_id, 2);
        recorder.acknowledge(&batch.cursor).unwrap();
        recorder.record_batch(vec![event(), event()], true).unwrap();
        let next = recorder.read(Some(&batch.cursor), 10).unwrap();
        assert_eq!(
            next.gap.unwrap(),
            Gap {
                first: 3,
                last: 4,
                previous_epoch: false
            }
        );
        assert_eq!(
            next.records
                .iter()
                .map(|record| record.event_id)
                .collect::<Vec<_>>(),
            vec![5, 6]
        );
        assert!(recorder.record_batch(vec![], true).is_err());
        assert!(
            recorder
                .record_batch((0..17).map(|_| event()).collect(), true)
                .is_err()
        );
    }
}
