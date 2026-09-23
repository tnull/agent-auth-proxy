//! Safe logical views; no authenticated request or raw response is serialized.
use super::pipeline::Guard;
use super::*;
use aap_observe::{Data, Direction, Emission, Flow, Inspection, Redaction, View};
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Clone, Default)]
pub(super) struct StreamState {
    bytes: u64,
    started: bool,
    ended: bool,
    media_type: Option<String>,
}
fn slot(direction: Direction, view: View) -> usize {
    match (direction, view) {
        (Direction::Outbound, View::Agent) => 0,
        (Direction::Outbound, View::Upstream) => 1,
        (Direction::Inbound, View::Agent) => 2,
        (Direction::Inbound, View::Upstream) => 3,
    }
}
fn emission(direction: Direction, view: View, data: Data) -> Emission {
    let inspection = if matches!(
        data,
        Data::FlowOpen { .. }
            | Data::FlowClose { .. }
            | Data::PolicyDecision { .. }
            | Data::AuthTransition { .. }
    ) {
        Inspection::MetadataOnly
    } else {
        Inspection::Parsed
    };
    Emission {
        direction,
        view,
        inspection,
        redaction: if inspection == Inspection::MetadataOnly {
            Redaction::Complete
        } else {
            Redaction::Transformed
        },
        data,
    }
}
impl Guard {
    pub fn record(&self, direction: Direction, data: Data) -> Result<()> {
        self.record_view(direction, View::Agent, data)
    }
    pub fn record_view(&self, direction: Direction, view: View, data: Data) -> Result<()> {
        self.record_many(vec![emission(direction, view, data)])
    }
    pub fn record_both(&self, direction: Direction, data: Data) -> Result<()> {
        self.record_many(vec![
            emission(direction, View::Agent, data.clone()),
            emission(direction, View::Upstream, data),
        ])
    }
    fn record_many(&self, emissions: Vec<Emission>) -> Result<()> {
        record_with(&self.flow, &self.observed, emissions, || Ok(()))
    }
    pub fn content(&self, direction: Direction, view: View, bytes: &[u8]) -> Result<()> {
        self.content_views(direction, &[view], bytes)
    }
    pub fn content_both(&self, direction: Direction, bytes: &[u8]) -> Result<()> {
        self.content_views(direction, &[View::Agent, View::Upstream], bytes)
    }
    fn content_views(&self, direction: Direction, views: &[View], bytes: &[u8]) -> Result<()> {
        for chunk in bytes.chunks(32 * 1024) {
            let events = {
                let states = self
                    .observed
                    .lock()
                    .map_err(|_| ErrorCode::ObservationUnavailable)?;
                views
                    .iter()
                    .map(|view| {
                        let state = &states[slot(direction, *view)];
                        emission(
                            direction,
                            *view,
                            Data::ContentChunk {
                                offset: state.bytes,
                                body_base64: STANDARD.encode(chunk),
                                media_type: state.media_type.clone(),
                                encoding: "base64".into(),
                            },
                        )
                    })
                    .collect()
            };
            self.record_many(events)?;
        }
        Ok(())
    }
    pub fn end_content(&self, direction: Direction, views: &[View]) -> Result<()> {
        let events = {
            let states = self
                .observed
                .lock()
                .map_err(|_| ErrorCode::ObservationUnavailable)?;
            views
                .iter()
                .map(|view| {
                    emission(
                        direction,
                        *view,
                        Data::ContentEnd {
                            complete: true,
                            bytes: states[slot(direction, *view)].bytes,
                            reason: None,
                        },
                    )
                })
                .collect()
        };
        self.record_many(events)
    }
    pub fn finish_observation(&self, complete: bool, reason: Option<ErrorCode>) -> Result<()> {
        finish_with(&self.flow, &self.observed, complete, reason, || Ok(()))
    }
}

fn record_with(
    flow: &Flow,
    observed: &Mutex<[StreamState; 4]>,
    emissions: Vec<Emission>,
    commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut states = observed
        .lock()
        .map_err(|_| ErrorCode::ObservationUnavailable)?;
    let mut next = states.clone();
    for event in &emissions {
        let state = &mut next[slot(event.direction, event.view)];
        match &event.data {
            Data::RequestStart { headers, .. } | Data::ResponseStart { headers, .. } => {
                if state.started {
                    return Err(ErrorCode::ObservationUnavailable.into());
                }
                state.started = true;
                state.media_type = headers
                    .iter()
                    .find(|(name, value)| name == "content-type" && value != "[redacted]")
                    .map(|(_, value)| value.clone());
            }
            Data::ContentChunk {
                offset,
                body_base64,
                ..
            } => {
                if !state.started || state.ended || *offset != state.bytes {
                    return Err(ErrorCode::ObservationUnavailable.into());
                }
                state.bytes += STANDARD
                    .decode(body_base64)
                    .map_err(|_| ErrorCode::ObservationUnavailable)?
                    .len() as u64;
            }
            Data::ContentEnd { bytes, .. } => {
                if state.ended || *bytes != state.bytes {
                    return Err(ErrorCode::ObservationUnavailable.into());
                }
                state.ended = true;
            }
            _ => {}
        }
    }
    flow.record_batch_with(emissions, commit)?;
    *states = next;
    Ok(())
}

pub(super) fn finish_with(
    flow: &Flow,
    observed: &Mutex<[StreamState; 4]>,
    complete: bool,
    reason: Option<ErrorCode>,
    commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let events = {
        let states = observed
            .lock()
            .map_err(|_| ErrorCode::ObservationUnavailable)?;
        let mut events = Vec::new();
        for view in [View::Agent, View::Upstream] {
            for direction in [Direction::Outbound, Direction::Inbound] {
                let state = &states[slot(direction, view)];
                if state.started && !state.ended {
                    events.push(emission(
                        direction,
                        view,
                        Data::ContentEnd {
                            complete,
                            bytes: state.bytes,
                            reason,
                        },
                    ));
                }
            }
            events.push(emission(
                Direction::Inbound,
                view,
                Data::FlowClose {
                    complete,
                    outbound_bytes: states[slot(Direction::Outbound, view)].bytes,
                    inbound_bytes: states[slot(Direction::Inbound, view)].bytes,
                    reason,
                },
            ));
        }
        events
    };
    record_with(flow, observed, events, commit)
}

pub(super) fn headers(headers: &http::HeaderMap) -> Vec<(String, String)> {
    safe_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or(""))),
    )
}
pub(super) fn request_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    safe_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    )
}
fn safe_headers<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<(String, String)> {
    headers
        .filter_map(|(name, value)| {
            let name = name.to_ascii_lowercase();
            let safe = match name.as_str() {
                "content-type" => match value.split(';').next().unwrap_or("").trim() {
                    "application/json" => "application/json",
                    "application/x-www-form-urlencoded" => "application/x-www-form-urlencoded",
                    "text/event-stream" => "text/event-stream",
                    "text/plain" => "text/plain",
                    _ => "[redacted]",
                },
                "anthropic-version" if value == "2023-06-01" => "2023-06-01",
                "content-encoding" if value == "identity" => "identity",
                "authorization" | "x-api-key" | "cookie" | "set-cookie" | "location"
                | "anthropic-version" | "content-encoding" | "accept" => "[redacted]",
                "content-length" | "transfer-encoding" | "connection" | "keep-alive" | "host" => {
                    return None;
                }
                _ => return Some(("[withheld]".into(), "[withheld]".into())),
            };
            Some((name, safe.into()))
        })
        .collect()
}
