use super::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone)]
pub struct Recorder {
    pub(super) state: Arc<Mutex<State>>,
}
pub(super) struct State {
    pub epoch: String,
    pub next: u64,
    pub records: BTreeMap<u64, Stored>,
    owner: VecDeque<u64>,
    pub subscribers: [Option<Subscriber>; 16],
    session_bytes: HashMap<String, usize>,
    bytes: usize,
    pub max_events: usize,
    pub max_bytes: usize,
    available: bool,
}
pub(super) struct Stored {
    pub record: Record,
    pub bytes: usize,
    required: bool,
    owner: bool,
    claims: u16,
}
pub(super) struct Subscriber {
    pub id: String,
    pub scope: Scope,
    pub limits: SubscriptionLimits,
    pub next: u64,
    pub issued: u64,
    pub queue: VecDeque<(u64, u64)>,
    pub bytes: usize,
}
impl State {
    pub fn release(&mut self, sources: &BTreeSet<u64>, subscriber: Option<usize>) {
        if let Some(index) = subscriber {
            if let Some(subscriber) = &mut self.subscribers[index] {
                subscriber.queue.retain(|(_, source)| {
                    if sources.contains(source) {
                        subscriber.bytes -= self.records[source].bytes;
                        false
                    } else {
                        true
                    }
                });
            }
        } else {
            self.owner.retain(|source| !sources.contains(source));
        }
        for source in sources {
            let Some(entry) = self.records.get_mut(source) else {
                continue;
            };
            if let Some(index) = subscriber {
                entry.claims &= !(1 << index);
            } else {
                entry.owner = false;
            }
            if !entry.owner && entry.claims == 0 {
                self.discard(*source);
            }
        }
    }
    fn remove(&mut self, sources: &BTreeSet<u64>) {
        self.owner.retain(|source| !sources.contains(source));
        for subscriber in self.subscribers.iter_mut().flatten() {
            subscriber.queue.retain(|(_, source)| {
                if sources.contains(source) {
                    subscriber.bytes -= self.records[source].bytes;
                    false
                } else {
                    true
                }
            });
        }
        for source in sources {
            self.discard(*source);
        }
    }
    fn discard(&mut self, source: u64) {
        if let Some(entry) = self.records.remove(&source) {
            self.bytes -= entry.bytes;
            if let Some(bytes) = self.session_bytes.get_mut(&entry.record.event.session_id) {
                *bytes -= entry.bytes;
                if *bytes == 0 {
                    self.session_bytes.remove(&entry.record.event.session_id);
                }
            }
        }
    }
    pub fn subscriber(&self, id: &str) -> Result<usize> {
        self.subscribers
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|subscriber| subscriber.id == id))
            .ok_or_else(|| ErrorCode::ObservationUnavailable.into())
    }
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
                records: BTreeMap::new(),
                owner: VecDeque::new(),
                subscribers: std::array::from_fn(|_| None),
                session_bytes: HashMap::new(),
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
    /// At most sixteen records / 256 KiB, accepted atomically into every
    /// applicable required queue. Best-effort queues may independently lose the
    /// complete update. Loss consumes source and selected delivery IDs.
    pub fn record_batch(&self, events: Vec<Event>, required: bool) -> Result<()> {
        self.record_batch_with(events, required, || Ok(()))
    }
    pub(super) fn record_batch_with(
        &self,
        events: Vec<Event>,
        required: bool,
        commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if events.is_empty() || events.len() > 16 {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let first = state.next;
        let previous_deliveries: [Option<u64>; 16] = std::array::from_fn(|index| {
            state.subscribers[index]
                .as_ref()
                .map(|subscriber| subscriber.next)
        });
        // Preflight only advances identity counters; evictions/publication occur
        // after the caller's commit. Undo those counters when it rejects, not
        // when actual recording loss must remain visible to consumers.
        let commit = |state: &mut State| {
            let result = commit();
            if result.is_err() {
                state.next = first;
                for (subscriber, previous) in state.subscribers.iter_mut().zip(previous_deliveries)
                {
                    if let (Some(subscriber), Some(previous)) = (subscriber, previous) {
                        subscriber.next = previous;
                    }
                }
            }
            result
        };
        state.next = first
            .checked_add(events.len() as u64)
            .ok_or(ErrorCode::ObservationUnavailable)?;
        let mut deliveries = Vec::with_capacity(events.len());
        for event in &events {
            let mut selected = [None; 16];
            for (index, subscriber) in state.subscribers.iter_mut().enumerate() {
                if let Some(subscriber) = subscriber
                    && subscriber.scope.permits(event)
                {
                    selected[index] = Some(subscriber.next);
                    subscriber.next = subscriber
                        .next
                        .checked_add(1)
                        .ok_or(ErrorCode::ObservationUnavailable)?;
                }
            }
            deliveries.push(selected);
        }
        fn unavailable(required: bool, commit: impl FnOnce() -> Result<()>) -> Result<()> {
            if required {
                Err(ErrorCode::ObservationUnavailable.into())
            } else {
                commit()
            }
        }
        if !state.available || events.len() > state.max_events {
            return unavailable(required, || commit(&mut state));
        }
        let time_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorCode::ObservationUnavailable)?
            .as_millis()
            .try_into()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let mut additions = Vec::with_capacity(events.len());
        let mut added_bytes = 0;
        let mut projected_sessions = state.session_bytes.clone();
        for (index, event) in events.into_iter().enumerate() {
            if !aap_types::ids::valid_id(&event.session_id, 16) || event_size(&event) > 128 * 1024 {
                return unavailable(required, || commit(&mut state));
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
                return unavailable(required, || commit(&mut state));
            }
            *projected_sessions
                .entry(record.event.session_id.clone())
                .or_default() += bytes;
            let claims = deliveries[index]
                .iter()
                .enumerate()
                .fold(0, |mask, (slot, delivery)| {
                    mask | if delivery.is_some() { 1 << slot } else { 0 }
                });
            additions.push(Stored {
                record,
                bytes,
                required,
                owner: true,
                claims,
            });
        }
        // Plan each consumer's eviction independently. No mutation is committed
        // unless the complete recording update also fits global/session budgets.
        let mut local_drops: [BTreeSet<u64>; 16] = std::array::from_fn(|_| BTreeSet::new());
        for (index, subscriber) in state.subscribers.iter().enumerate() {
            let Some(subscriber) = subscriber else {
                continue;
            };
            let (selected, bytes) = additions
                .iter()
                .filter(|entry| entry.claims & (1 << index) != 0)
                .fold((0, 0), |(count, bytes), entry| {
                    (count + 1, bytes + entry.bytes)
                });
            if selected == 0 {
                continue;
            }
            let mut accepted =
                selected <= subscriber.limits.max_events && bytes <= subscriber.limits.max_bytes;
            let mut count = subscriber.queue.len() + selected;
            let mut total = subscriber.bytes + bytes;
            for (_, source) in &subscriber.queue {
                if !accepted
                    || (count <= subscriber.limits.max_events
                        && total <= subscriber.limits.max_bytes)
                {
                    break;
                }
                let entry = &state.records[source];
                if required || entry.required {
                    accepted = false;
                    break;
                }
                local_drops[index].insert(*source);
                count -= 1;
                total -= entry.bytes;
            }
            if !accepted {
                if required {
                    return unavailable(required, || commit(&mut state));
                }
                // A consumer-local best-effort loss must not discard an update
                // accepted by the owner or another consumer. Consume delivery
                // identities, but retain none of this update in this queue.
                local_drops[index].clear();
                for (entry, selected) in additions.iter_mut().zip(&mut deliveries) {
                    entry.claims &= !(1 << index);
                    selected[index] = None;
                }
            }
        }
        let mut global_drops = BTreeSet::new();
        let mut projected_bytes = state.bytes + added_bytes;
        let mut projected_count = state.records.len() + additions.len();
        for (source, entry) in &state.records {
            if !entry.owner
                && (0..16).all(|index| {
                    entry.claims & (1 << index) == 0 || local_drops[index].contains(source)
                })
            {
                global_drops.insert(*source);
                projected_bytes -= entry.bytes;
                projected_count -= 1;
                *projected_sessions
                    .get_mut(&entry.record.event.session_id)
                    .unwrap() -= entry.bytes;
            }
        }
        let fits = |bytes: usize, count: usize, sessions: &HashMap<String, usize>| {
            bytes <= state.max_bytes
                && count <= state.max_events
                && sessions.values().all(|bytes| *bytes <= 8 * 1024 * 1024)
        };
        for (source, entry) in &state.records {
            if fits(projected_bytes, projected_count, &projected_sessions) {
                break;
            }
            if global_drops.contains(source) {
                continue;
            }
            if required || entry.required {
                return unavailable(required, || commit(&mut state));
            }
            global_drops.insert(*source);
            projected_bytes -= entry.bytes;
            projected_count -= 1;
            *projected_sessions
                .get_mut(&entry.record.event.session_id)
                .unwrap() -= entry.bytes;
        }
        if !fits(projected_bytes, projected_count, &projected_sessions) {
            return unavailable(required, || commit(&mut state));
        }
        commit(&mut state)?;
        for (index, sources) in local_drops.into_iter().enumerate() {
            if !sources.is_empty() {
                state.release(&sources, Some(index));
            }
        }
        if !global_drops.is_empty() {
            state.remove(&global_drops);
        }
        for (entry, selected) in additions.into_iter().zip(deliveries) {
            let source = entry.record.event_id;
            for (index, delivery) in selected.into_iter().enumerate() {
                if let Some(delivery) = delivery
                    && let Some(subscriber) = &mut state.subscribers[index]
                {
                    subscriber.queue.push_back((delivery, source));
                    subscriber.bytes += entry.bytes;
                }
            }
            state.bytes += entry.bytes;
            *state
                .session_bytes
                .entry(entry.record.event.session_id.clone())
                .or_default() += entry.bytes;
            state.owner.push_back(source);
            state.records.insert(source, entry);
        }
        Ok(())
    }
    pub fn read(&self, cursor: Option<&Cursor>, limit: usize) -> Result<Batch> {
        self.read_bounded(cursor, limit, 64 * 1024 * 1024 + 2048)
    }
    pub fn read_bounded(
        &self,
        cursor: Option<&Cursor>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Batch> {
        page_bounds(limit, max_bytes)?;
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
            .owner
            .iter()
            .find(|source| **source > after)
            .copied()
            .unwrap_or(state.next);
        let gap = (previous_epoch || first > after + 1).then_some(Gap {
            first: after + 1,
            last: first - 1,
            previous_epoch,
        });
        let mut records = Vec::new();
        let mut position = first;
        let mut bytes = 512;
        for source in &state.owner {
            if *source < first {
                continue;
            }
            if *source != position || records.len() == limit {
                break;
            }
            let entry = &state.records[source];
            if bytes + entry.bytes + 1 > max_bytes {
                if records.is_empty() {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                break;
            }
            bytes += entry.bytes + 1;
            records.push(entry.record.clone());
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
        let removed: BTreeSet<_> = state
            .owner
            .iter()
            .copied()
            .take_while(|id| *id <= cursor.after)
            .collect();
        state.release(&removed, None);
        Ok(())
    }
    pub fn set_available(&self, available: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.available = available;
        }
    }
}
pub(super) fn page_bounds(limit: usize, max_bytes: usize) -> Result<()> {
    if limit == 0 || limit > 1024 || !(512..=64 * 1024 * 1024 + 2048).contains(&max_bytes) {
        return Err(ErrorCode::RequestInvalid.into());
    }
    Ok(())
}
fn event_size(event: &Event) -> usize {
    event.session_id.len()
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
            } => body_base64.len() + media_type.as_ref().map_or(0, String::len) + encoding.len(),
            Data::RequestStart {
                method,
                target,
                headers,
            } => {
                method.len()
                    + target.len()
                    + headers
                        .iter()
                        .map(|(k, v)| k.len() + v.len())
                        .sum::<usize>()
            }
            Data::ResponseStart { headers, .. } => {
                headers.iter().map(|(k, v)| k.len() + v.len()).sum()
            }
            Data::AuthTransition { item_id, .. } => item_id.len(),
            _ => 0,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_claims_and_budgets_remain_consistent_under_churn() {
        let id = || aap_types::ids::random_id(16).unwrap();
        let sessions = [id(), id()];
        let recorder = Recorder::new(id(), 10, 16 * 1024).unwrap();
        let enroll = || {
            recorder
                .subscribe(
                    Scope {
                        sessions: sessions.to_vec(),
                        views: vec![View::Agent, View::Upstream],
                        classes: vec![ContentClass::Metadata],
                    },
                    SubscriptionLimits {
                        max_events: 3,
                        max_bytes: 8192,
                    },
                )
                .unwrap()
        };
        let mut subscribers = vec![enroll(), enroll()];
        let mut losses = 0;
        for step in 0..128 {
            let flow = Flow::new(
                recorder.clone(),
                FlowContext {
                    session_id: sessions[step % 2].clone(),
                    request_id: Some(id()),
                    parent_request_id: None,
                    policy_version: 1,
                    protocol: Protocol::Http1,
                },
                step % 5 == 0,
            )
            .unwrap();
            let _ = flow.record_batch(
                [View::Agent, View::Upstream]
                    .into_iter()
                    .map(|view| Emission {
                        direction: Direction::Outbound,
                        view,
                        inspection: Inspection::MetadataOnly,
                        redaction: Redaction::Complete,
                        data: Data::FlowOpen {},
                    })
                    .collect(),
            );
            if step % 3 == 0 {
                let batch = recorder.read(None, 3).unwrap();
                losses += usize::from(batch.gap.is_some());
                recorder.acknowledge(&batch.cursor).unwrap();
            }
            if step % 4 == 0 {
                let batch = subscribers[step % 2].read(None, 2, 8192).unwrap();
                losses += usize::from(batch.gap.is_some());
                subscribers[step % 2].acknowledge(&batch.cursor).unwrap();
            }
            if step % 7 == 0 {
                subscribers.remove(0);
                subscribers.push(enroll());
            }
            let state = recorder.state.lock().unwrap();
            assert!(state.records.len() <= state.max_events);
            assert!(state.bytes <= state.max_bytes);
            assert_eq!(
                state.bytes,
                state
                    .records
                    .values()
                    .map(|entry| entry.bytes)
                    .sum::<usize>()
            );
            let mut session_bytes = HashMap::new();
            for (source, entry) in &state.records {
                *session_bytes
                    .entry(entry.record.event.session_id.clone())
                    .or_insert(0) += entry.bytes;
                assert_eq!(entry.owner, state.owner.contains(source));
                let claims =
                    state
                        .subscribers
                        .iter()
                        .enumerate()
                        .fold(0, |mask, (index, subscriber)| {
                            mask | if subscriber.as_ref().is_some_and(|subscriber| {
                                subscriber.queue.iter().any(|(_, id)| id == source)
                            }) {
                                1 << index
                            } else {
                                0
                            }
                        });
                assert_eq!(entry.claims, claims);
                assert!(
                    entry.owner || entry.claims != 0,
                    "unclaimed record was retained"
                );
            }
            assert_eq!(session_bytes, state.session_bytes);
            for source in &state.owner {
                assert!(state.records[source].owner);
            }
            for subscriber in state.subscribers.iter().flatten() {
                assert!(subscriber.queue.len() <= subscriber.limits.max_events);
                assert!(subscriber.bytes <= subscriber.limits.max_bytes);
                assert_eq!(
                    subscriber.bytes,
                    subscriber
                        .queue
                        .iter()
                        .map(|(_, source)| state.records[source].bytes)
                        .sum::<usize>()
                );
                let mut previous = 0;
                for (delivery, source) in &subscriber.queue {
                    assert!(*delivery > previous && *delivery < subscriber.next);
                    assert!(
                        subscriber
                            .scope
                            .permits(&state.records[source].record.event)
                    );
                    previous = *delivery;
                }
            }
        }
        assert!(losses > 0, "test did not exercise loss or retention gaps");
    }
}
