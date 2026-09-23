use super::*;
use aap_auth::placeholders::ImmediatePlaceholderRedactor;
use aap_transport::tcp::relay::{self, Gate};
use base64::{Engine, engine::general_purpose::STANDARD};

pub(super) struct Observation {
    flow: Flow,
    inspection: Inspection,
    directions: [Observed; 2],
}
#[derive(Default)]
struct Observed {
    redactor: ImmediatePlaceholderRedactor,
    offset: u64,
    ended: bool,
}
impl Observation {
    pub fn new(flow: Flow, inspection: stream::Inspection) -> Self {
        Self {
            flow,
            inspection: match inspection {
                stream::Inspection::PlaintextBytes => Inspection::PlaintextBytes,
                stream::Inspection::Opaque => Inspection::Opaque,
                stream::Inspection::MetadataOnly => Inspection::MetadataOnly,
            },
            directions: [Observed::default(), Observed::default()],
        }
    }
    fn emissions(&self, direction: Direction, data: Data) -> Vec<Emission> {
        [View::Agent, View::Upstream]
            .into_iter()
            .map(|view| Emission {
                direction,
                view,
                inspection: self.inspection,
                redaction: if self.inspection == Inspection::MetadataOnly {
                    Redaction::Withheld
                } else {
                    Redaction::Transformed
                },
                data: data.clone(),
            })
            .collect()
    }
    pub fn finish(
        &self,
        complete: bool,
        cause: stream::Cause,
        sent: u64,
        received: u64,
    ) -> Result<()> {
        let reason = (!complete).then(|| state::reason(cause));
        let mut events = Vec::with_capacity(6);
        for (index, direction) in [Direction::Outbound, Direction::Inbound]
            .into_iter()
            .enumerate()
        {
            let observed = &self.directions[index];
            if !observed.ended {
                events.extend(self.emissions(
                    direction,
                    Data::ContentEnd {
                        complete,
                        bytes: observed.offset,
                        reason,
                    },
                ));
            }
        }
        for view in [View::Agent, View::Upstream] {
            events.push(Emission {
                direction: Direction::Outbound,
                view,
                inspection: Inspection::MetadataOnly,
                redaction: Redaction::Complete,
                data: Data::FlowClose {
                    complete,
                    outbound_bytes: sent,
                    inbound_bytes: received,
                    reason,
                },
            });
        }
        self.flow.record_batch(events)
    }
}
fn direction(value: relay::Direction) -> (usize, Direction) {
    match value {
        relay::Direction::Outbound => (0, Direction::Outbound),
        relay::Direction::Inbound => (1, Direction::Inbound),
    }
}
impl Gate for Observation {
    fn before_forward(
        &mut self,
        value: relay::Direction,
        bytes: &[u8],
    ) -> std::result::Result<(), stream::Cause> {
        let (index, direction) = direction(value);
        if self.directions[index].ended {
            return Err(stream::Cause::InternalError);
        }
        let safe = if self.inspection == Inspection::MetadataOnly {
            bytes::Bytes::new()
        } else {
            self.directions[index]
                .redactor
                .feed(bytes, false)
                .map_err(|_| stream::Cause::ObservationUnavailable)?
        };
        // Even an entirely withheld continuation needs fresh required-channel
        // admission. An empty safe chunk is not an empty application DATA frame.
        self.flow
            .record_batch(self.emissions(
                direction,
                Data::ContentChunk {
                    offset: self.directions[index].offset,
                    body_base64: STANDARD.encode(&safe),
                    media_type: None,
                    encoding: "base64".into(),
                },
            ))
            .map_err(|_| stream::Cause::ObservationUnavailable)?;
        self.directions[index].offset += safe.len() as u64;
        Ok(())
    }
    fn before_end(&mut self, value: relay::Direction) -> std::result::Result<(), stream::Cause> {
        let (index, direction) = direction(value);
        if self.directions[index].ended {
            return Err(stream::Cause::InternalError);
        }
        self.directions[index]
            .redactor
            .feed(&[], true)
            .map_err(|_| stream::Cause::ObservationUnavailable)?;
        self.flow
            .record_batch(self.emissions(
                direction,
                Data::ContentEnd {
                    complete: true,
                    bytes: self.directions[index].offset,
                    reason: None,
                },
            ))
            .map_err(|_| stream::Cause::ObservationUnavailable)?;
        self.directions[index].ended = true;
        Ok(())
    }
}
