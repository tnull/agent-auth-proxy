use super::*;

pub(super) struct Relay {
    application: Box<dyn ApplicationIo>,
    outgoing_buffer: Box<[u8]>,
    outgoing: Option<Output>,
    incoming: Bytes,
    sent: u64,
    admitted: u64,
    send_limit: u64,
    sent_end: bool,
    received_end: bool,
    stalls: [Option<Instant>; 2],
    final_deadline: Option<Instant>,
    idle_timeout: Duration,
    turn: bool,
}
struct Output {
    encoded: stream::Encoded,
    header_offset: usize,
    payload_offset: usize,
    end: bool,
}
impl Relay {
    pub(super) fn new(application: Box<dyn ApplicationIo>, opened: &stream::Opened) -> Self {
        Self {
            application,
            outgoing_buffer: vec![0; opened.max_data_bytes as usize].into_boxed_slice(),
            outgoing: None,
            incoming: Bytes::new(),
            sent: 0,
            admitted: 0,
            send_limit: opened.send_limit,
            sent_end: false,
            received_end: false,
            stalls: [None, None],
            final_deadline: None,
            idle_timeout: Duration::from_millis(opened.idle_timeout_ms),
            turn: false,
        }
    }
    pub(super) fn deadline(&self, lifetime: Instant, idle: Instant) -> Instant {
        if let Some(deadline) = self.final_deadline {
            deadline.min(lifetime + Duration::from_secs(2))
        } else {
            self.stalls
                .iter()
                .flatten()
                .copied()
                .fold(lifetime.min(idle), Instant::min)
        }
    }
    fn output(
        &mut self,
        reader: &mut Reader,
        sequence: &mut Sequence,
        idle: &mut Instant,
        cx: &mut Context<'_>,
    ) -> Poll<Result<()>> {
        if self.sent_end {
            return Poll::Pending;
        }
        if let Some(output) = &mut self.outgoing {
            if output.header_offset < 5 {
                let bytes = &output.encoded.header[output.header_offset..];
                match Pin::new(&mut reader.io).poll_write(cx, bytes) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(count)) if count > 0 && count <= bytes.len() => {
                        output.header_offset += count;
                        // A terminal reply can already be readable after this
                        // write. Commit directional end before polling input.
                        if output.header_offset == 5 && output.end {
                            self.sent_end = true;
                            self.outgoing = None;
                            self.stalls[0] = None;
                        }
                    }
                    _ => return Poll::Ready(Err(ErrorCode::ResultUnavailable.into())),
                }
            } else {
                let bytes = &output.encoded.payload[output.payload_offset..];
                match Pin::new(&mut reader.io).poll_write(cx, bytes) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(count)) if count > 0 && count <= bytes.len() => {
                        output.payload_offset += count;
                        self.sent += count as u64;
                        let now = Instant::now();
                        *idle = now + self.idle_timeout;
                        if output.payload_offset == output.encoded.payload.len() {
                            self.outgoing = None;
                            self.stalls[0] = None;
                        } else {
                            self.stalls[0] = Some(now + self.idle_timeout);
                        }
                    }
                    _ => return Poll::Ready(Err(ErrorCode::ResultUnavailable.into())),
                }
            }
            return Poll::Ready(Ok(()));
        }
        // One byte beyond an exhausted budget distinguishes exact-limit END
        // from excess application bytes. The excess is never transmitted.
        let remaining = self.send_limit - self.admitted;
        let room = self.outgoing_buffer.len().min(remaining.max(1) as usize);
        let count = std::task::ready!(
            self.application
                .poll_read(cx, &mut self.outgoing_buffer[..room])
        )
        .map_err(|_| ErrorCode::ResultUnavailable)?;
        if count > room {
            return Poll::Ready(Err(ErrorCode::InternalError.into()));
        }
        if count as u64 > remaining {
            return Poll::Ready(Err(ErrorCode::LimitExceeded.into()));
        }
        let frame = if count == 0 {
            Frame::SendEnd
        } else {
            Frame::Data(Bytes::copy_from_slice(&self.outgoing_buffer[..count]))
        };
        sequence.accept(Sender::Agent, &frame)?;
        self.admitted += count as u64;
        self.outgoing = Some(Output {
            encoded: frame.encode()?,
            header_offset: 0,
            payload_offset: 0,
            end: count == 0,
        });
        self.stalls[0] = Some(Instant::now() + self.idle_timeout);
        Poll::Ready(Ok(()))
    }
    fn input(
        &mut self,
        reader: &mut Reader,
        sequence: &mut Sequence,
        idle: &mut Instant,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<stream::Terminal>>> {
        if !self.incoming.is_empty() {
            let count = std::task::ready!(self.application.poll_write(cx, &self.incoming))
                .map_err(|_| ErrorCode::ResultUnavailable)?;
            if count == 0 || count > self.incoming.len() {
                return Poll::Ready(Err(ErrorCode::ResultUnavailable.into()));
            }
            self.incoming = if count == self.incoming.len() {
                Bytes::new()
            } else {
                self.incoming.slice(count..)
            };
            let now = Instant::now();
            *idle = now + self.idle_timeout;
            self.stalls[1] = if self.incoming.is_empty() {
                None
            } else {
                Some(now + self.idle_timeout)
            };
            return Poll::Ready(Ok(None));
        }
        if sequence.ended(Sender::Daemon) && !self.received_end {
            std::task::ready!(self.application.poll_send_end(cx))
                .map_err(|_| ErrorCode::ResultUnavailable)?;
            self.received_end = true;
            self.stalls[1] = None;
            return Poll::Ready(Ok(None));
        }
        match std::task::ready!(reader.next(sequence, cx))? {
            Frame::Data(bytes) => {
                self.incoming = bytes;
                self.stalls[1] = Some(Instant::now() + self.idle_timeout);
                Poll::Ready(Ok(None))
            }
            Frame::SendEnd => {
                self.stalls[1] = Some(Instant::now() + self.idle_timeout);
                Poll::Ready(Ok(None))
            }
            Frame::Terminal(value) => {
                if !reader.input.is_empty()
                    || value.sent_bytes > self.sent
                    || (value.operation.state == aap_types::OperationState::Completed
                        && (!self.sent_end || !self.received_end || self.outgoing.is_some()))
                {
                    return Poll::Ready(Err(ErrorCode::ResultUnavailable.into()));
                }
                Poll::Ready(Ok(Some(value)))
            }
            _ => Poll::Ready(Err(ErrorCode::ResultUnavailable.into())),
        }
    }
    fn poll(
        &mut self,
        reader: &mut Reader,
        sequence: &mut Sequence,
        lifetime: Instant,
        idle: &mut Instant,
        cx: &mut Context<'_>,
    ) -> Poll<Result<stream::Terminal>> {
        let mut blocked = 0;
        for _ in 0..16 {
            if Instant::now() >= self.deadline(lifetime, *idle) {
                return Poll::Ready(Err(ErrorCode::ResultUnavailable.into()));
            }
            self.turn = !self.turn;
            let step = if self.turn {
                self.input(reader, sequence, idle, cx)
            } else {
                self.output(reader, sequence, idle, cx)
                    .map(|result| result.map(|()| None))
            };
            match step {
                Poll::Ready(Ok(Some(terminal))) => return Poll::Ready(Ok(terminal)),
                Poll::Ready(Ok(None)) => blocked = 0,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    blocked += 1;
                    if blocked == 2 {
                        return Poll::Pending;
                    }
                }
            }
            if self.sent_end && self.received_end && self.final_deadline.is_none() {
                self.final_deadline = Some(Instant::now() + Duration::from_secs(2));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl State {
    pub(super) fn relay(&mut self, cx: &mut Context<'_>) -> Poll<Result<stream::Terminal>> {
        let relay = self.relay.as_mut().ok_or(ErrorCode::ResultUnavailable)?;
        relay.poll(
            &mut self.reader,
            &mut self.sequence,
            self.lifetime,
            &mut self.idle,
            cx,
        )
    }
}
