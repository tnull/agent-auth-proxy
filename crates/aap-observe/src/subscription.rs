use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    Metadata,
    Content,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub sessions: Vec<String>,
    pub views: Vec<View>,
    pub classes: Vec<ContentClass>,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionLimits {
    pub max_events: usize,
    pub max_bytes: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCursor {
    pub epoch: String,
    pub subscription_id: String,
    pub after: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Delivery {
    pub delivery_id: u64,
    pub record: Record,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SubscriptionBatch {
    pub deliveries: Vec<Delivery>,
    pub gap: Option<Gap>,
    pub cursor: SubscriptionCursor,
}
pub struct Subscription {
    pub(super) recorder: Recorder,
    pub(super) id: String,
}
impl Recorder {
    /// Trusted enrollment of a forward-only, immutable content grant.
    /// The handle confers only this subscription's read/ack authority.
    pub fn subscribe(&self, scope: Scope, limits: SubscriptionLimits) -> Result<Subscription> {
        scope.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        if limits.max_events == 0
            || limits.max_events > state.max_events
            || !(512..=state.max_bytes).contains(&limits.max_bytes)
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let index = state
            .subscribers
            .iter()
            .position(Option::is_none)
            .ok_or(ErrorCode::LimitExceeded)?;
        let id = aap_types::ids::random_id(16).map_err(|_| ErrorCode::ObservationUnavailable)?;
        state.subscribers[index] = Some(super::recorder::Subscriber {
            id: id.clone(),
            scope,
            limits,
            next: 1,
            issued: 0,
            queue: VecDeque::new(),
            bytes: 0,
        });
        Ok(Subscription {
            recorder: self.clone(),
            id,
        })
    }
}
impl Subscription {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn read(
        &self,
        cursor: Option<&SubscriptionCursor>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<SubscriptionBatch> {
        super::recorder::page_bounds(limit, max_bytes)?;
        let mut state = self
            .recorder
            .state
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let index = state.subscriber(&self.id)?;
        let subscriber = state.subscribers[index]
            .as_ref()
            .ok_or(ErrorCode::ObservationUnavailable)?;
        let after = cursor.map_or(0, |cursor| cursor.after);
        if cursor
            .is_some_and(|cursor| cursor.subscription_id != self.id || cursor.epoch != state.epoch)
            || after > subscriber.issued
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let first = subscriber
            .queue
            .iter()
            .find(|(id, _)| *id > after)
            .map_or(subscriber.next, |(id, _)| *id);
        let gap = (first > after + 1).then_some(Gap {
            first: after + 1,
            last: first - 1,
            previous_epoch: false,
        });
        let mut deliveries = Vec::new();
        let mut position = first;
        let mut bytes = 512;
        for (delivery_id, source) in &subscriber.queue {
            if *delivery_id < first {
                continue;
            }
            if *delivery_id != position || deliveries.len() == limit {
                break;
            }
            let delivery = Delivery {
                delivery_id: *delivery_id,
                record: state.records[source].record.clone(),
            };
            let size = serde_json::to_vec(&delivery)
                .map_err(|_| ErrorCode::ObservationUnavailable)?
                .len();
            if bytes + size + 1 > max_bytes {
                if deliveries.is_empty() {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                break;
            }
            bytes += size + 1;
            deliveries.push(delivery);
            position += 1;
        }
        let cursor = SubscriptionCursor {
            epoch: state.epoch.clone(),
            subscription_id: self.id.clone(),
            after: position - 1,
        };
        let subscriber = state.subscribers[index]
            .as_mut()
            .ok_or(ErrorCode::ObservationUnavailable)?;
        subscriber.issued = subscriber.issued.max(cursor.after);
        Ok(SubscriptionBatch {
            deliveries,
            gap,
            cursor,
        })
    }
    pub fn acknowledge(&self, cursor: &SubscriptionCursor) -> Result<()> {
        let mut state = self
            .recorder
            .state
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let index = state.subscriber(&self.id)?;
        let subscriber = state.subscribers[index]
            .as_ref()
            .ok_or(ErrorCode::ObservationUnavailable)?;
        if cursor.subscription_id != self.id
            || cursor.epoch != state.epoch
            || cursor.after > subscriber.issued
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let sources: std::collections::BTreeSet<_> = subscriber
            .queue
            .iter()
            .take_while(|(id, _)| *id <= cursor.after)
            .map(|(_, source)| *source)
            .collect();
        state.release(&sources, Some(index));
        Ok(())
    }
    pub fn close(&self) {
        if let Ok(mut state) = self.recorder.state.lock()
            && let Ok(index) = state.subscriber(&self.id)
        {
            let sources: std::collections::BTreeSet<_> = state.subscribers[index]
                .as_ref()
                .into_iter()
                .flat_map(|subscriber| subscriber.queue.iter().map(|(_, source)| *source))
                .collect();
            state.release(&sources, Some(index));
            state.subscribers[index] = None;
        }
    }
}
impl Scope {
    fn validate(&self) -> Result<()> {
        if self.sessions.is_empty()
            || self.sessions.len() > 64
            || self
                .sessions
                .iter()
                .any(|id| !aap_types::ids::valid_id(id, 16))
            || self
                .sessions
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != self.sessions.len()
            || self.views.is_empty()
            || self.views.len() > 2
            || self.views.first() == self.views.get(1)
            || self.classes.is_empty()
            || self.classes.len() > 2
            || self.classes.first() == self.classes.get(1)
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(())
    }
    pub(super) fn permits(&self, event: &Event) -> bool {
        let class = match &event.data {
            Data::ContentChunk { .. } => ContentClass::Content,
            Data::FlowOpen {}
            | Data::FlowClose { .. }
            | Data::PolicyDecision { .. }
            | Data::ConnectAdmission { .. }
            | Data::RequestStart { .. }
            | Data::ResponseStart { .. }
            | Data::ContentEnd { .. }
            | Data::AuthTransition { .. } => ContentClass::Metadata,
        };
        self.sessions.contains(&event.session_id)
            && self.views.contains(&event.view)
            && self.classes.contains(&class)
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id() -> String {
        aap_types::ids::random_id(16).unwrap()
    }
    fn event(session: &str, content: bool) -> Event {
        Event {
            session_id: session.into(),
            request_id: Some(id()),
            parent_request_id: None,
            flow_id: id(),
            stream_id: "inbound.upstream".into(),
            sequence: 0,
            protocol: Protocol::Http1,
            inspection: Inspection::Parsed,
            redaction: Redaction::Transformed,
            policy_version: 1,
            direction: Direction::Inbound,
            view: View::Upstream,
            data: if content {
                Data::ContentChunk {
                    offset: 0,
                    body_base64: "aGVsbG8=".into(),
                    media_type: Some("text/plain".into()),
                    encoding: "base64".into(),
                }
            } else {
                Data::ResponseStart {
                    status: 200,
                    headers: vec![],
                }
            },
        }
    }
    fn scope(session: &str) -> Scope {
        Scope {
            sessions: vec![session.into()],
            views: vec![View::Upstream],
            classes: vec![ContentClass::Metadata],
        }
    }
    fn limits(events: usize) -> SubscriptionLimits {
        SubscriptionLimits {
            max_events: events,
            max_bytes: 8192,
        }
    }
    #[test]
    fn owner_cursors_cannot_be_confused_with_scoped_delivery_cursors() {
        let value = serde_json::json!({"epoch":id(),"subscription_id":id(),"after":1});
        assert!(
            serde_json::from_value::<Cursor>(value).is_err(),
            "owner accepted a delivery cursor as a source cursor"
        );
    }
    #[test]
    fn subscription_admission_is_explicit_and_delivery_excludes_ungranted_events() {
        let recorder = Recorder::new(id(), 32, 32768).unwrap();
        let (a, b) = (id(), id());
        recorder.record(event(&a, false), false).unwrap();
        let subscriber = recorder
            .subscribe(scope(&a), limits(16))
            .expect("scoped subscription must be admitted");
        assert!(
            subscriber
                .read(None, 16, 8192)
                .unwrap()
                .deliveries
                .is_empty(),
            "subscription silently included pre-enrollment history"
        );
        recorder.record(event(&b, false), false).unwrap();
        recorder.record(event(&a, true), false).unwrap();
        let mut other_view = event(&a, false);
        other_view.view = View::Agent;
        recorder.record(other_view, false).unwrap();
        recorder.record(event(&a, false), false).unwrap();
        let batch = subscriber.read(None, 16, 8192).unwrap();
        assert_eq!(batch.deliveries.len(), 1);
        assert_eq!(batch.deliveries[0].delivery_id, 1);
        assert_eq!(batch.deliveries[0].record.event.session_id, a);
        assert_eq!(batch.deliveries[0].record.event_id, 5);
        assert!(batch.gap.is_none(), "filtering is not recording loss");
        let mut invalid = scope(&a);
        invalid.sessions.clear();
        assert!(recorder.subscribe(invalid, limits(16)).is_err());
        let mut invalid = scope(&a);
        invalid.views.push(View::Upstream);
        assert!(recorder.subscribe(invalid, limits(16)).is_err());
        let mut invalid = scope(&a);
        invalid.classes.clear();
        assert!(recorder.subscribe(invalid, limits(16)).is_err());
    }
    #[test]
    fn acknowledgments_are_scoped_and_required_retention_waits_for_each_claim() {
        let recorder = Recorder::new(id(), 1, 8192).unwrap();
        let session = id();
        let a = recorder.subscribe(scope(&session), limits(1)).unwrap();
        let b = recorder.subscribe(scope(&session), limits(1)).unwrap();
        recorder.record(event(&session, false), true).unwrap();
        let one = a.read(None, 1, 8192).unwrap();
        assert!(b.acknowledge(&one.cursor).is_err());
        assert!(b.read(Some(&one.cursor), 1, 8192).is_err());
        let mut forged = one.cursor.clone();
        forged.after = 2;
        assert!(a.acknowledge(&forged).is_err());
        let mut forged = one.cursor.clone();
        forged.epoch = id();
        assert!(a.read(Some(&forged), 1, 8192).is_err());
        recorder
            .acknowledge(&recorder.read(None, 1).unwrap().cursor)
            .unwrap();
        a.acknowledge(&one.cursor).unwrap();
        assert!(
            recorder.record(event(&session, false), true).is_err(),
            "one consumer discarded another consumer's retained required event"
        );
        let two = b.read(None, 1, 8192).unwrap();
        assert_eq!(
            two.deliveries[0].record.event_id,
            one.deliveries[0].record.event_id
        );
        b.acknowledge(&two.cursor).unwrap();
        recorder.record(event(&session, false), true).unwrap();
        let next = a.read(Some(&one.cursor), 1, 8192).unwrap();
        assert_eq!(next.gap.unwrap().first, 2);
        assert_eq!(next.deliveries[0].delivery_id, 3);
    }
    #[test]
    fn a_slow_best_effort_consumer_loses_only_its_own_queue_and_reports_the_gap() {
        let recorder = Recorder::new(id(), 8, 32768).unwrap();
        let session = id();
        let small = recorder.subscribe(scope(&session), limits(2)).unwrap();
        let large = recorder.subscribe(scope(&session), limits(8)).unwrap();
        for _ in 0..3 {
            recorder.record(event(&session, false), false).unwrap();
        }
        let batch = small.read(None, 8, 8192).unwrap();
        assert_eq!(batch.deliveries.len(), 2);
        assert_eq!(
            batch.gap.unwrap(),
            Gap {
                first: 1,
                last: 1,
                previous_epoch: false
            }
        );
        assert_eq!(large.read(None, 8, 8192).unwrap().deliveries.len(), 3);
        assert_eq!(recorder.read(None, 8).unwrap().records.len(), 3);
        small.acknowledge(&batch.cursor).unwrap();
        assert_eq!(large.read(None, 8, 8192).unwrap().deliveries.len(), 3);
        assert_eq!(recorder.read(None, 8).unwrap().records.len(), 3);
        small.close();
        assert!(small.read(None, 1, 8192).is_err());
        assert!(small.acknowledge(&batch.cursor).is_err());
    }
    #[test]
    fn subscriber_count_and_encoded_page_budgets_are_finite() {
        let recorder = Recorder::new(id(), 32, 32768).unwrap();
        let session = id();
        let subscribers: Vec<_> = (0..16)
            .map(|_| recorder.subscribe(scope(&session), limits(16)).unwrap())
            .collect();
        assert!(recorder.subscribe(scope(&session), limits(16)).is_err());
        recorder.record(event(&session, false), true).unwrap();
        let batch = subscribers[0].read(None, 16, 8192).unwrap();
        let budget = 512 + serde_json::to_vec(&batch.deliveries[0]).unwrap().len() + 1;
        recorder.record(event(&session, false), true).unwrap();
        let page = subscribers[0].read(None, 16, budget).unwrap();
        assert_eq!(page.deliveries.len(), 1);
        assert!(serde_json::to_vec(&page).unwrap().len() <= budget);
        assert!(subscribers[0].read(None, 16, 512).is_err());
        drop(subscribers);
        assert!(recorder.subscribe(scope(&session), limits(16)).is_ok());
    }
    #[test]
    fn best_effort_consumer_overflow_cannot_drop_other_consumers_recording() {
        let recorder = Recorder::new(id(), 8, 32768).unwrap();
        let session = id();
        let small = recorder.subscribe(scope(&session), limits(1)).unwrap();
        let large = recorder.subscribe(scope(&session), limits(8)).unwrap();
        recorder
            .record_batch(vec![event(&session, false), event(&session, false)], false)
            .unwrap();
        assert_eq!(
            recorder.read(None, 8).unwrap().records.len(),
            2,
            "small consumer dropped owner recording"
        );
        assert_eq!(large.read(None, 8, 8192).unwrap().deliveries.len(), 2);
        let lost = small.read(None, 8, 8192).unwrap();
        assert!(lost.deliveries.is_empty());
        assert_eq!(
            lost.gap.unwrap(),
            Gap {
                first: 1,
                last: 2,
                previous_epoch: false
            }
        );
        recorder.record(event(&session, false), true).unwrap();
        recorder.record(event(&session, false), false).unwrap();
        assert_eq!(recorder.read(None, 8).unwrap().records.len(), 4);
        assert_eq!(large.read(None, 8, 8192).unwrap().deliveries.len(), 4);
        let retained = small.read(Some(&lost.cursor), 8, 8192).unwrap();
        assert_eq!(retained.deliveries.len(), 1);
        assert_eq!(
            retained.deliveries[0].record.event_id, 3,
            "required event was displaced"
        );
        assert_eq!(
            small
                .read(Some(&retained.cursor), 8, 8192)
                .unwrap()
                .gap
                .unwrap()
                .first,
            4
        );
    }
    #[test]
    fn per_session_retention_is_bounded_and_shared_records_are_charged_once() {
        let recorder = Recorder::new(id(), 512, 16 * 1024 * 1024).unwrap();
        let (a, b) = (id(), id());
        let mut input = event(&a, true);
        if let Data::ContentChunk { body_base64, .. } = &mut input.data {
            *body_base64 = "x".repeat(64 * 1024);
        }
        let mut grant = scope(&a);
        grant.classes = vec![ContentClass::Content];
        let large = SubscriptionLimits {
            max_events: 512,
            max_bytes: 16 * 1024 * 1024,
        };
        let one = recorder.subscribe(grant.clone(), large).unwrap();
        let two = recorder.subscribe(grant, large).unwrap();
        for _ in 0..150 {
            if recorder.record(input.clone(), true).is_err() {
                break;
            }
        }
        let state = recorder.state.lock().unwrap();
        assert!(
            state.records.len() >= 100,
            "consumer copies were charged as distinct payloads"
        );
        let charged: usize = state
            .records
            .values()
            .filter(|entry| entry.record.event.session_id == a)
            .map(|entry| entry.bytes)
            .sum();
        assert!(
            charged <= 8 * 1024 * 1024,
            "one session exceeded the 8 MiB retained-content ceiling"
        );
        drop(state);
        assert!(recorder.record(input.clone(), true).is_err());
        input.session_id = b;
        recorder.record(input, true).unwrap();
        drop((one, two));
    }
}
