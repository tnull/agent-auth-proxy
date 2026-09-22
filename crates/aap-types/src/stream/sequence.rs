use super::*;

/// Bidirectional framing state. Engine authorization, actual socket write counts,
/// deadlines, and aggregate buffer reservations remain the caller's responsibility.
pub struct Sequence {
    operation: Open,
    pending: bool,
    opened: Option<Opened>,
    directions: [Direction; 2],
    terminal: bool,
}

#[derive(Default)]
struct Direction {
    ended: bool,
    bytes: u64,
    frames: u32,
}

impl Sequence {
    pub fn new(operation: Open) -> Result<Self> {
        operation.validate()?;
        Ok(Self {
            operation,
            pending: false,
            opened: None,
            directions: [Direction::default(), Direction::default()],
            terminal: false,
        })
    }

    /// Call before reserving/reading a payload. This does not advance state.
    pub fn check_header(&self, sender: Sender, header: Header) -> Result<()> {
        if self.terminal
            || (sender == Sender::Agent && !matches!(header.kind, Kind::Data | Kind::SendEnd))
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        match header.kind {
            Kind::Pending if self.pending || self.is_opened() => {
                Err(ErrorCode::RequestInvalid.into())
            }
            Kind::Opened if self.is_opened() => Err(ErrorCode::RequestInvalid.into()),
            Kind::Data | Kind::SendEnd => {
                let opened = self.opened.as_ref().ok_or(ErrorCode::RequestInvalid)?;
                let direction = &self.directions[sender.index()];
                if direction.ended {
                    return Err(ErrorCode::RequestInvalid.into());
                }
                if header.kind == Kind::Data {
                    let limit = if sender == Sender::Agent {
                        opened.send_limit
                    } else {
                        opened.receive_limit
                    };
                    if header.length > opened.max_data_bytes as usize
                        || direction.frames >= MAX_DATA_FRAMES
                        || header.length as u64 > limit.saturating_sub(direction.bytes)
                    {
                        return Err(ErrorCode::LimitExceeded.into());
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Validate and atomically advance one complete frame. Invalid input leaves
    /// this state unchanged; the owning adapter must fail that attachment.
    pub fn accept(&mut self, sender: Sender, frame: &Frame) -> Result<()> {
        let header = frame.header()?;
        self.check_header(sender, header)?;
        match frame {
            Frame::Pending(value) => {
                if value.request_id != self.operation.request_id {
                    return Err(ErrorCode::RequestInvalid.into());
                }
                self.pending = true;
            }
            Frame::Opened(value) => {
                if value.request_id != self.operation.request_id
                    || value.resource != self.operation.resource
                {
                    return Err(ErrorCode::RequestInvalid.into());
                }
                self.opened = Some(value.clone());
            }
            Frame::Data(bytes) => {
                let direction = &mut self.directions[sender.index()];
                direction.bytes += bytes.len() as u64;
                direction.frames += 1;
            }
            Frame::SendEnd => self.directions[sender.index()].ended = true,
            Frame::Terminal(value) => {
                self.check_terminal(value)?;
                self.terminal = true;
            }
        }
        Ok(())
    }

    fn check_terminal(&self, value: &Terminal) -> Result<()> {
        let sent = &self.directions[Sender::Agent.index()];
        let received = &self.directions[Sender::Daemon.index()];
        if value.operation.request_id != self.operation.request_id
            || value.sent_bytes > sent.bytes
            || value.received_bytes > received.bytes
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        if value.operation.state == OperationState::Completed {
            if !self.is_opened()
                || !sent.ended
                || !received.ended
                || value.sent_bytes != sent.bytes
                || value.received_bytes != received.bytes
            {
                return Err(ErrorCode::RequestInvalid.into());
            }
        } else if self.is_opened() && value.operation.state != OperationState::OutcomeUnknown {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(())
    }

    pub fn is_opened(&self) -> bool {
        self.opened.is_some()
    }
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }
    pub fn ended(&self, sender: Sender) -> bool {
        self.directions[sender.index()].ended
    }
}
