//! Trusted bounded recording. Payloads must be sanitized by their owning adapter.
use aap_types::{ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub session_id: String,
    pub request_id: String,
    pub stream_id: String,
    pub policy_version: u64,
    pub direction: Direction,
    pub view: View,
    pub data: Data,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Outbound,
    Inbound,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum View {
    Agent,
    Upstream,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum Data {
    RequestStart {
        method: String,
        target: String,
    },
    ResponseStart {
        status: u16,
    },
    ContentChunk {
        offset: u64,
        body_base64: String,
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let id = state.next;
        state.next = state
            .next
            .checked_add(1)
            .ok_or(ErrorCode::ObservationUnavailable)?;
        let size_hint = event.session_id.len()
            + event.request_id.len()
            + event.stream_id.len()
            + match &event.data {
                Data::ContentChunk { body_base64, .. } => body_base64.len(),
                Data::RequestStart { method, target } => method.len() + target.len(),
                Data::AuthTransition { item_id, .. } => item_id.len(),
                _ => 0,
            };
        if !state.available || size_hint > 128 * 1024 {
            return if required {
                Err(ErrorCode::ObservationUnavailable.into())
            } else {
                Ok(())
            };
        }
        let record = Record {
            schema_version: 1,
            daemon_epoch: state.epoch.clone(),
            event_id: id,
            time_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ErrorCode::ObservationUnavailable)?
                .as_millis()
                .try_into()
                .map_err(|_| ErrorCode::ObservationUnavailable)?,
            event,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| ErrorCode::ObservationUnavailable)?
            .len();
        if bytes > state.max_bytes {
            return if required {
                Err(ErrorCode::ObservationUnavailable.into())
            } else {
                Ok(())
            };
        }
        while state.records.len() >= state.max_events || state.bytes + bytes > state.max_bytes {
            if required {
                return Err(ErrorCode::ObservationUnavailable.into());
            }
            if state
                .records
                .front()
                .is_some_and(|(_, _, protected)| *protected)
            {
                return Ok(());
            }
            if let Some((_, removed, _)) = state.records.pop_front() {
                state.bytes -= removed;
            } else {
                break;
            }
        }
        state.bytes += bytes;
        state.records.push_back((record, bytes, required));
        Ok(())
    }
    pub fn read(&self, cursor: Option<&Cursor>, limit: usize) -> Result<Batch> {
        if limit == 0 || limit > 1024 {
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
        for (record, _, _) in &state.records {
            if record.event_id < first {
                continue;
            }
            if record.event_id != position || records.len() == limit {
                break;
            }
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
            request_id: aap_types::ids::random_id(16).unwrap(),
            stream_id: "response".into(),
            policy_version: 1,
            direction: Direction::Inbound,
            view: View::Agent,
            data: Data::ResponseStart { status: 200 },
        }
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
}
