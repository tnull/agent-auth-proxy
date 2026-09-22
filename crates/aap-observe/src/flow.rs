//! Finite, flow-owned ordering state. Callers supply only sanitized event data.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http1,
    JsonRpc,
    Tcp,
    Tls,
    Control,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Inspection {
    Parsed,
    PlaintextBytes,
    Opaque,
    MetadataOnly,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Redaction {
    Complete,
    Transformed,
    Withheld,
    Truncated,
}
#[derive(Clone)]
pub struct FlowContext {
    pub session_id: String,
    pub request_id: Option<String>,
    pub parent_request_id: Option<String>,
    pub policy_version: u64,
    pub protocol: Protocol,
}
pub struct Emission {
    pub direction: Direction,
    pub view: View,
    pub inspection: Inspection,
    pub redaction: Redaction,
    pub data: Data,
}
#[derive(Clone)]
pub struct Flow(Arc<Inner>);
struct Inner {
    recorder: Recorder,
    context: FlowContext,
    id: String,
    required: bool,
    sequences: Mutex<[u64; 4]>,
}
impl Flow {
    pub fn record_batch(&self, emissions: Vec<Emission>) -> Result<()> {
        if emissions.is_empty() || emissions.len() > 16 {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let mut sequences = self
            .0
            .sequences
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let context = &self.0.context;
        let mut events = Vec::with_capacity(emissions.len());
        for Emission {
            direction,
            view,
            inspection,
            redaction,
            data,
        } in emissions
        {
            let slot = match (direction, view) {
                (Direction::Outbound, View::Agent) => 0,
                (Direction::Outbound, View::Upstream) => 1,
                (Direction::Inbound, View::Agent) => 2,
                (Direction::Inbound, View::Upstream) => 3,
            };
            let sequence = sequences[slot];
            sequences[slot] = sequence
                .checked_add(1)
                .ok_or(ErrorCode::ObservationUnavailable)?;
            events.push(Event {
                session_id: context.session_id.clone(),
                request_id: context.request_id.clone(),
                parent_request_id: context.parent_request_id.clone(),
                flow_id: self.0.id.clone(),
                stream_id: match (direction, view) {
                    (Direction::Outbound, View::Agent) => "outbound.agent",
                    (Direction::Outbound, View::Upstream) => "outbound.upstream",
                    (Direction::Inbound, View::Agent) => "inbound.agent",
                    (Direction::Inbound, View::Upstream) => "inbound.upstream",
                }
                .into(),
                sequence,
                protocol: context.protocol,
                inspection,
                redaction,
                policy_version: context.policy_version,
                direction,
                view,
                data,
            });
        }
        self.0.recorder.record_batch(events, self.0.required)
    }
    pub fn new(recorder: Recorder, context: FlowContext, required: bool) -> Result<Self> {
        if !aap_types::ids::valid_id(&context.session_id, 16)
            || context
                .request_id
                .as_ref()
                .is_some_and(|id| !aap_types::ids::valid_id(id, 16))
            || context
                .parent_request_id
                .as_ref()
                .is_some_and(|id| !aap_types::ids::valid_id(id, 16))
            || context.policy_version == 0
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let id = aap_types::ids::random_id(16).map_err(|_| ErrorCode::ObservationUnavailable)?;
        Ok(Self(Arc::new(Inner {
            recorder,
            context,
            id,
            required,
            sequences: Mutex::new([0; 4]),
        })))
    }
    pub fn id(&self) -> &str {
        &self.0.id
    }
    pub fn record(
        &self,
        direction: Direction,
        view: View,
        inspection: Inspection,
        redaction: Redaction,
        data: Data,
    ) -> Result<()> {
        self.record_batch(vec![Emission {
            direction,
            view,
            inspection,
            redaction,
            data,
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> FlowContext {
        FlowContext {
            session_id: aap_types::ids::random_id(16).unwrap(),
            request_id: Some(aap_types::ids::random_id(16).unwrap()),
            parent_request_id: None,
            policy_version: 7,
            protocol: Protocol::Http1,
        }
    }
    fn record(flow: &Flow, direction: Direction, view: View) -> Result<()> {
        flow.record(
            direction,
            view,
            Inspection::Parsed,
            Redaction::Transformed,
            Data::ResponseStart {
                status: 200,
                headers: vec![],
            },
        )
    }
    #[test]
    fn each_directional_view_has_its_own_sequence_and_shared_flow_identity() {
        let recorder =
            Recorder::new(aap_types::ids::random_id(16).unwrap(), 32, 64 * 1024).unwrap();
        let context = context();
        let id = context.request_id.clone().unwrap();
        let flow = Flow::new(recorder.clone(), context, true).expect("flow construction failed");
        assert!(aap_types::ids::valid_id(flow.id(), 16));
        for _ in 0..2 {
            for direction in [Direction::Outbound, Direction::Inbound] {
                for view in [View::Agent, View::Upstream] {
                    record(&flow, direction, view).unwrap();
                }
            }
        }
        let records = recorder.read(None, 32).unwrap().records;
        assert_eq!(records.len(), 8);
        assert_eq!(
            records
                .iter()
                .map(|record| &record.event.stream_id)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            4,
            "each directional view needs a distinct stream identity"
        );
        for (index, record) in records.iter().enumerate() {
            let event = serde_json::to_value(&record.event).unwrap();
            assert_eq!(event["flow_id"], flow.id());
            assert_eq!(event["request_id"], id);
            assert_eq!(event["sequence"], index / 4);
            assert_eq!(event["protocol"], "http1");
            assert_eq!(event["inspection"], "parsed");
            assert_eq!(event["redaction"], "transformed");
            assert_eq!(event["policy_version"], 7);
            assert!(event["parent_request_id"].is_null());
        }
    }
    #[test]
    fn concurrent_clones_serialize_sequences_without_a_global_stream_registry() {
        let recorder =
            Recorder::new(aap_types::ids::random_id(16).unwrap(), 128, 128 * 1024).unwrap();
        let flow = Flow::new(recorder.clone(), context(), true).expect("flow construction failed");
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let flow = flow.clone();
                scope.spawn(move || {
                    for _ in 0..8 {
                        record(&flow, Direction::Inbound, View::Agent).unwrap();
                    }
                });
            }
        });
        let records = recorder.read(None, 128).unwrap().records;
        assert_eq!(records.len(), 64);
        for (index, record) in records.iter().enumerate() {
            assert_eq!(
                serde_json::to_value(&record.event).unwrap()["sequence"],
                index
            );
        }
    }
    #[test]
    fn failed_required_recording_leaves_a_sequence_gap_and_validates_identity() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 1, 8192).unwrap();
        let flow = Flow::new(recorder.clone(), context(), true).expect("flow construction failed");
        record(&flow, Direction::Inbound, View::Upstream).unwrap();
        assert!(record(&flow, Direction::Inbound, View::Upstream).is_err());
        let first = recorder.read(None, 1).unwrap();
        recorder.acknowledge(&first.cursor).unwrap();
        record(&flow, Direction::Inbound, View::Upstream).unwrap();
        let next = recorder.read(Some(&first.cursor), 1).unwrap();
        assert_eq!(next.gap.unwrap().first, 2);
        assert_eq!(
            serde_json::to_value(&next.records[0].event).unwrap()["sequence"],
            2
        );
        let mut invalid = context();
        invalid.session_id = "caller header".into();
        assert!(Flow::new(recorder.clone(), invalid, false).is_err());
        let mut invalid = context();
        invalid.parent_request_id = Some("forged trace".into());
        assert!(Flow::new(recorder.clone(), invalid, false).is_err());
        let mut tcp = context();
        tcp.request_id = None;
        tcp.protocol = Protocol::Tcp;
        assert!(Flow::new(recorder, tcp, false).is_ok());
    }
    #[test]
    fn paired_flow_views_share_atomic_channel_acceptance() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 2, 8192).unwrap();
        let flow = Flow::new(recorder.clone(), context(), true).unwrap();
        let pair = || {
            [View::Agent, View::Upstream]
                .into_iter()
                .map(|view| Emission {
                    direction: Direction::Inbound,
                    view,
                    inspection: Inspection::Parsed,
                    redaction: Redaction::Transformed,
                    data: Data::ResponseStart {
                        status: 200,
                        headers: vec![],
                    },
                })
                .collect()
        };
        flow.record_batch(pair())
            .expect("paired flow emission refused");
        let first = recorder.read(None, 10).unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(flow.record_batch(pair()).is_err());
        recorder.acknowledge(&first.cursor).unwrap();
        flow.record_batch(pair()).unwrap();
        let next = recorder.read(Some(&first.cursor), 10).unwrap();
        assert_eq!(next.records.len(), 2);
        assert!(next.records.iter().all(|record| record.event.sequence == 2));
        assert_eq!(next.gap.unwrap().first, 3);
    }
}
