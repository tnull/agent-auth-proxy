//! Observation-only suppression of recognizable placeholder representations.
//! This transform confers no authority and does not change agent-facing data.
use aap_types::{ErrorCode, Result};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use bytes::Bytes;

const DECODED_LEN: usize = 51;
const MAX_ENCODED: usize = DECODED_LEN * 6;
#[derive(Default)]
pub struct PlaceholderRedactor {
    pending: Vec<u8>,
    done: bool,
}
impl PlaceholderRedactor {
    /// Return sanitized observation bytes and the number of original bytes
    /// consumed, including any retained by previous calls. Callers may release
    /// that source prefix only after accepting its required observation.
    pub fn feed(&mut self, chunk: &[u8], end: bool) -> Result<(Bytes, usize)> {
        if self.done || chunk.len() > 256 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        self.pending.extend_from_slice(chunk);
        let mut output = Vec::new();
        let mut position = 0;
        while position < self.pending.len() && (end || self.pending.len() - position >= MAX_ENCODED)
        {
            if let Some(count) = recognizable(&self.pending[position..]) {
                output.extend_from_slice(b"[redacted]");
                position += count;
            } else {
                output.push(self.pending[position]);
                position += 1;
            }
        }
        self.pending.drain(..position);
        self.done = end;
        Ok((output.into(), position))
    }
}

fn recognizable(input: &[u8]) -> Option<usize> {
    // A complete token is always 51 ASCII bytes: an eight-byte kind prefix and
    // a canonical 32-byte random ID encoded as unpadded base64url.
    if input.starts_with(b"YWFw") && input.len() >= 68 {
        for engine in [STANDARD, URL_SAFE] {
            let mut value = [0; DECODED_LEN];
            if engine.decode_slice(&input[..68], &mut value).ok() == Some(DECODED_LEN)
                && valid(&value)
            {
                return Some(68);
            }
        }
    }
    if !matches!(input.first(), Some(b'a' | b'%' | b'\\')) {
        return None;
    }
    let mut decoded = [0; DECODED_LEN];
    let mut position = 0;
    for byte in &mut decoded {
        let next = input.get(position..)?;
        let (value, count) = match next.first()? {
            b'%' => (hex(*next.get(1)?)? * 16 + hex(*next.get(2)?)?, 3),
            b'\\' if next.starts_with(b"\\u00") => {
                (hex(*next.get(4)?)? * 16 + hex(*next.get(5)?)?, 6)
            }
            value => (*value, 1),
        };
        if !value.is_ascii_alphanumeric() && !matches!(value, b'_' | b'-') {
            return None;
        }
        *byte = value;
        position += count;
    }
    valid(&decoded).then_some(position)
}
fn valid(value: &[u8; DECODED_LEN]) -> bool {
    matches!(&value[..8], b"aap_un1_" | b"aap_pw1_" | b"aap_cs1_")
        && std::str::from_utf8(&value[8..]).is_ok_and(|id| aap_types::ids::valid_id(id, 32))
}
fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token(prefix: &str) -> String {
        format!("{prefix}{}", aap_types::ids::random_id(32).unwrap())
    }
    #[test]
    fn suppresses_recognizable_placeholders_at_every_chunk_boundary() {
        for prefix in ["aap_un1_", "aap_pw1_", "aap_cs1_"] {
            let value = token(prefix);
            let representations = [
                value.clone(),
                value.replace("aap_", "%61ap_"),
                value.replace("aap_", "\\u0061ap_"),
                value.bytes().map(|byte| format!("%{byte:02X}")).collect(),
                value.bytes().map(|byte| format!("\\u{byte:04x}")).collect(),
                STANDARD.encode(&value),
                URL_SAFE.encode(&value),
            ];
            for encoded in representations {
                let input = format!("before {encoded} after");
                for split in 0..=input.len() {
                    let mut redactor = PlaceholderRedactor::default();
                    let (bytes, first) = redactor.feed(&input.as_bytes()[..split], false).unwrap();
                    let (last, second) = redactor.feed(&input.as_bytes()[split..], true).unwrap();
                    let mut output = bytes.to_vec();
                    output.extend_from_slice(&last);
                    assert_eq!(
                        output, b"before [redacted] after",
                        "split {split}: {encoded}"
                    );
                    assert_eq!(first + second, input.len());
                }
            }
        }
    }
    #[test]
    fn ordinary_data_and_partial_lookalikes_survive_with_finite_state() {
        let input = b"aap_pw1_short %ZZ \\u00xz YWFwX3 short ordinary ";
        let mut redactor = PlaceholderRedactor::default();
        let mut output = Vec::new();
        let mut consumed = 0;
        for byte in input {
            let (bytes, count) = redactor.feed(&[*byte], false).unwrap();
            output.extend(bytes);
            consumed += count;
        }
        let (bytes, count) = redactor.feed(&[], true).unwrap();
        output.extend(bytes);
        consumed += count;
        assert_eq!(output, input);
        assert_eq!(consumed, input.len());
        assert!(
            redactor.feed(&[], true).is_err(),
            "a completed stream cannot restart"
        );
        assert!(
            PlaceholderRedactor::default()
                .feed(&vec![b'x'; 256 * 1024 + 1], false)
                .is_err()
        );
        let mut redactor = PlaceholderRedactor::default();
        for _ in 0..64 {
            redactor.feed(&vec![b'a'; 4096], false).unwrap();
            assert!(redactor.pending.len() < MAX_ENCODED);
        }
    }
}
