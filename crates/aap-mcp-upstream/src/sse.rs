use crate::{MAX_REQUEST, MAX_RESPONSE};
use aap_types::{ErrorCode, Result};

/// Incremental framing only: returned event data is PRIVATE, unvalidated
/// upstream input. Pass it through Profile::response before any delivery.
/// No cursor, retry schedule, reconnection, or HTTP client is created here.
#[derive(Default)]
pub struct SseDecoder {
    line: Vec<u8>,
    data: Vec<u8>,
    event: bool,
    unsupported_event: bool,
    seen_line: bool,
    after_cr: bool,
    bytes: usize,
    events: usize,
    failed: bool,
}

impl SseDecoder {
    /// Accept at most 256 KiB per call and 1 MiB over this decoder's lifetime.
    /// Any error permanently poisons the decoder; no partial batch is returned.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.line = Vec::new();
            self.data = Vec::new();
        }
        result
    }

    fn push_inner(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        if self.failed {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        if bytes.len() > MAX_REQUEST || bytes.len() > MAX_RESPONSE - self.bytes {
            return Err(ErrorCode::LimitExceeded.into());
        }
        self.bytes += bytes.len();
        let mut messages = Vec::new();
        for byte in bytes {
            if self.after_cr {
                self.after_cr = false;
                if *byte == b'\n' {
                    continue;
                }
            }
            if matches!(byte, b'\r' | b'\n') {
                self.after_cr = *byte == b'\r';
                if let Some(message) = self.line()? {
                    messages.push(message);
                }
            } else {
                if self.line.len() == MAX_REQUEST {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                self.line.push(*byte);
            }
        }
        Ok(messages)
    }

    fn line(&mut self) -> Result<Option<Vec<u8>>> {
        let line = std::mem::take(&mut self.line);
        let line = std::str::from_utf8(&line).map_err(|_| ErrorCode::InspectionUnavailable)?;
        let line = if self.seen_line {
            line
        } else {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        };
        self.seen_line = true;
        if line.is_empty() {
            self.events += 1;
            if self.events > 128 {
                return Err(ErrorCode::LimitExceeded.into());
            }
            self.event = false;
            if self.unsupported_event {
                return Err(ErrorCode::InspectionUnavailable.into());
            }
            // Each data field contributed a trailing newline. Empty priming
            // data and comments produce no message, but still consume budgets.
            self.data.pop();
            if self.data.is_empty() {
                return Ok(None);
            }
            return Ok(Some(std::mem::take(&mut self.data)));
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => {
                if value.len() + 1 > MAX_RESPONSE - self.data.len() {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                self.data.extend_from_slice(value.as_bytes());
                self.data.push(b'\n');
            }
            "event" => {
                self.event = true;
                self.unsupported_event = !value.is_empty() && value != "message";
            }
            // SSE ignores unknown fields. IDs and retry hints are likewise
            // discarded here: none may become an upstream resume capability.
            _ => {}
        }
        Ok(None)
    }

    /// Framing completion only; the caller must also have exactly one final
    /// response. An unterminated event never becomes a successful MCP result.
    pub fn finish(self) -> Result<()> {
        if self.failed || !self.line.is_empty() || !self.data.is_empty() || self.event {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        Ok(())
    }
}
