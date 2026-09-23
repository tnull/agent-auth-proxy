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
    /// Commit a bounded state change before records become visible. Required
    /// recording failure skips the callback; best-effort loss does not. Callback
    /// rejection preserves prior records and identities. The callback must not
    /// block, reenter this recorder/flow, or publish effects and then return Err.
    pub fn record_batch_with(
        &self,
        emissions: Vec<Emission>,
        commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if emissions.is_empty() || emissions.len() > 16 {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let mut sequences = self
            .0
            .sequences
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let previous = *sequences;
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
        let mut rejected = false;
        let result = self
            .0
            .recorder
            .record_batch_with(events, self.0.required, || {
                let result = commit();
                rejected = result.is_err();
                result
            });
        if rejected {
            *sequences = previous;
        }
        result
    }
    pub fn record_batch(&self, emissions: Vec<Emission>) -> Result<()> {
        self.record_batch_with(emissions, || Ok(()))
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
    fn ending() -> Vec<Emission> {
        [View::Agent, View::Upstream]
            .into_iter()
            .map(|view| Emission {
                direction: Direction::Inbound,
                view,
                inspection: Inspection::MetadataOnly,
                redaction: Redaction::Complete,
                data: Data::FlowClose {
                    complete: true,
                    outbound_bytes: 0,
                    inbound_bytes: 0,
                    reason: None,
                },
            })
            .collect()
    }

    #[test]
    fn conditional_batch_rejection_preserves_records_and_sequences() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 2, 8192).unwrap();
        let context = context();
        let subscriber = recorder
            .subscribe(
                Scope {
                    sessions: vec![context.session_id.clone()],
                    views: vec![View::Agent, View::Upstream],
                    classes: vec![ContentClass::Metadata],
                },
                SubscriptionLimits {
                    max_events: 2,
                    max_bytes: 8192,
                },
            )
            .unwrap();
        let flow = Flow::new(recorder.clone(), context, false).unwrap();
        flow.record_batch(ending()).unwrap();
        let first = recorder.read(None, 16).unwrap();
        let delivered = subscriber.read(None, 16, 8192).unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(
            matches!(flow.record_batch_with(ending(), || Err(ErrorCode::SessionInvalid.into())),
            Err(error) if error.code == ErrorCode::SessionInvalid)
        );
        let retained = recorder.read(None, 16).unwrap();
        assert!(
            retained.gap.is_none(),
            "rejected completion evicted existing evidence"
        );
        assert_eq!(retained.records[0].event_id, first.records[0].event_id);
        let retained = subscriber.read(None, 16, 8192).unwrap();
        assert!(retained.gap.is_none());
        assert_eq!(
            retained.deliveries[0].record.event_id,
            first.records[0].event_id
        );
        recorder.acknowledge(&first.cursor).unwrap();
        subscriber.acknowledge(&delivered.cursor).unwrap();
        flow.record_batch_with(ending(), || Ok(())).unwrap();
        let next = recorder.read(Some(&first.cursor), 16).unwrap();
        assert!(
            next.gap.is_none(),
            "rejected completion consumed event identities"
        );
        assert_eq!(next.records.len(), 2);
        assert!(next.records.iter().all(|record| record.event.sequence == 1));
        let next = subscriber.read(Some(&delivered.cursor), 16, 8192).unwrap();
        assert!(
            next.gap.is_none(),
            "rejected completion consumed delivery identities"
        );
        assert_eq!(next.deliveries.len(), 2);
        assert_eq!(next.deliveries[0].delivery_id, 3);
    }

    #[test]
    fn conditional_batch_rejected_loss_preserves_identities() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 2, 8192).unwrap();
        let required = Flow::new(recorder.clone(), context(), true).unwrap();
        required.record_batch(ending()).unwrap();
        let first = recorder.read(None, 16).unwrap();
        let flow = Flow::new(recorder.clone(), context(), false).unwrap();
        assert!(
            matches!(flow.record_batch_with(ending(), || Err(ErrorCode::SessionInvalid.into())),
            Err(error) if error.code == ErrorCode::SessionInvalid)
        );
        recorder.acknowledge(&first.cursor).unwrap();
        flow.record_batch_with(ending(), || Ok(())).unwrap();
        let next = recorder.read(Some(&first.cursor), 16).unwrap();
        assert!(
            next.gap.is_none(),
            "rejected completion manufactured an observation gap"
        );
        assert_eq!(next.records.len(), 2);
        assert!(next.records.iter().all(|record| record.event.sequence == 0));
    }

    #[test]
    fn conditional_batch_cannot_publish_before_state_commit() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 2, 8192).unwrap();
        let flow = Flow::new(recorder.clone(), context(), true).unwrap();
        let mut committed = false;
        flow.record_batch_with(ending(), || {
            assert!(
                matches!(
                    recorder.state.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ),
                "records can become visible before their state commit"
            );
            committed = true;
            Ok(())
        })
        .unwrap();
        assert!(committed);
        assert_eq!(recorder.read(None, 16).unwrap().records.len(), 2);
    }

    #[test]
    fn conditional_batch_required_capacity_failure_never_commits() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 2, 8192).unwrap();
        let flow = Flow::new(recorder.clone(), context(), true).unwrap();
        flow.record_batch(ending()).unwrap();
        let mut committed = false;
        assert!(
            matches!(flow.record_batch_with(ending(), || { committed = true; Ok(()) }),
            Err(error) if error.code == ErrorCode::ObservationUnavailable)
        );
        assert!(!committed);
        assert_eq!(recorder.read(None, 16).unwrap().records.len(), 2);
    }

    #[test]
    fn conditional_batch_best_effort_loss_still_commits_once() {
        let recorder = Recorder::new(aap_types::ids::random_id(16).unwrap(), 2, 8192).unwrap();
        Flow::new(recorder.clone(), context(), true)
            .unwrap()
            .record_batch(ending())
            .unwrap();
        let first = recorder.read(None, 16).unwrap();
        let flow = Flow::new(recorder.clone(), context(), false).unwrap();
        let mut commits = 0;
        flow.record_batch_with(ending(), || {
            commits += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(commits, 1);
        assert_eq!(recorder.read(None, 16).unwrap().records.len(), 2);
        let lost = recorder.read(Some(&first.cursor), 16).unwrap();
        assert!(lost.records.is_empty());
        assert_eq!(lost.gap.unwrap().first, 3);
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
