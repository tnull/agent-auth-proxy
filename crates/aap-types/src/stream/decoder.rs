use super::*;
use bytes::BytesMut;

/// One decoder per direction, retaining at most one bounded payload. The owner
/// reserves aggregate memory before use, bounds retained output frames, and
/// enforces cancellation/deadlines while waiting for more input.
#[derive(Default)]
pub struct Decoder {
    prefix: [u8; 5],
    prefix_len: usize,
    header: Option<Header>,
    payload: BytesMut,
    failed: bool,
}

impl Decoder {
    /// Consume only the prefix of input needed for one frame. None means more
    /// input is needed; a completed frame advances the shared Sequence once.
    /// An invalid header is rejected before consuming/allocating its payload.
    pub fn next(
        &mut self,
        input: &mut &[u8],
        sequence: &mut Sequence,
        sender: Sender,
    ) -> Result<Option<Frame>> {
        if self.failed {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let result = self.decode_next(input, sequence, sender);
        if result.is_err() {
            self.failed = true;
            self.payload = BytesMut::new();
        }
        result
    }

    fn decode_next(
        &mut self,
        input: &mut &[u8],
        sequence: &mut Sequence,
        sender: Sender,
    ) -> Result<Option<Frame>> {
        if !input.is_empty()
            && (sequence.is_terminal() || (sender == Sender::Agent && !sequence.is_opened()))
        {
            // Before OPENED even a partial client header is forbidden input.
            return Err(ErrorCode::RequestInvalid.into());
        }
        if self.header.is_none() {
            let take = (5 - self.prefix_len).min(input.len());
            self.prefix[self.prefix_len..self.prefix_len + take].copy_from_slice(&input[..take]);
            self.prefix_len += take;
            *input = &input[take..];
            if self.prefix_len != 5 {
                return Ok(None);
            }
            let header = Header::parse(self.prefix)?;
            sequence.check_header(sender, header)?;
            self.payload = BytesMut::with_capacity(header.length);
            self.header = Some(header);
        }
        let header = self.header.expect("validated header");
        // The opposite direction may have terminated while this payload waited.
        sequence.check_header(sender, header)?;
        let take = (header.length - self.payload.len()).min(input.len());
        self.payload.extend_from_slice(&input[..take]);
        *input = &input[take..];
        if self.payload.len() != header.length {
            return Ok(None);
        }
        let frame = Frame::decode(header, std::mem::take(&mut self.payload).freeze())?;
        sequence.accept(sender, &frame)?;
        self.prefix_len = 0;
        self.header = None;
        Ok(Some(frame))
    }

    /// Socket EOF is complete only after a whole terminal record. SEND_END is
    /// application half-close, never permission to omit the final outcome.
    pub fn finish(&self, sequence: &Sequence) -> Result<()> {
        if self.failed || self.prefix_len != 0 || self.header.is_some() || !sequence.is_terminal() {
            return Err(ErrorCode::ResultUnavailable.into());
        }
        Ok(())
    }
}
