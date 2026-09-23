//! Conservative observation for interactive streams, with no withheld payload.
use super::*;

#[derive(Default)]
pub struct ImmediatePlaceholderRedactor {
    pending: Vec<u8>,
    done: bool,
}
impl ImmediatePlaceholderRedactor {
    /// Every source byte is immediately represented by safe output or by an
    /// already emitted redaction marker. A possible token suffix at a chunk
    /// boundary is masked conservatively, including false positives. Previously
    /// masked bytes are never restored after a later mismatch. No store access
    /// or dictionary of real credentials is needed. A feed accepts at most
    /// 256 KiB, retains at most 305 already-masked source bytes, and returns at
    /// most the input chunk length plus one nine-byte marker.
    pub fn feed(&mut self, chunk: &[u8], end: bool) -> Result<Bytes> {
        if self.done || chunk.len() > 256 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let hidden = self.pending.len();
        self.pending.extend_from_slice(chunk);
        let input = std::mem::take(&mut self.pending);
        let mut output = Vec::with_capacity(chunk.len() + 10);
        let mut position = 0;
        while position < input.len() {
            match candidate(&input[position..]) {
                Candidate::Complete(count) => {
                    if position >= hidden {
                        output.extend_from_slice(b"[redacted]");
                    }
                    position += count;
                }
                Candidate::Partial => {
                    if position >= hidden {
                        output.extend_from_slice(b"[redacted]");
                    }
                    if !end {
                        self.pending.extend_from_slice(&input[position..]);
                    }
                    break;
                }
                Candidate::No => {
                    if position >= hidden {
                        output.push(input[position]);
                    }
                    position += 1;
                }
            }
        }
        self.done = end;
        Ok(output.into())
    }
}

enum Candidate {
    No,
    Partial,
    Complete(usize),
}

fn candidate(input: &[u8]) -> Candidate {
    if input[0] == b'Y' {
        if input.len() < 4 {
            return if b"YWFw".starts_with(input) {
                Candidate::Partial
            } else {
                Candidate::No
            };
        }
        if !input.starts_with(b"YWFw") {
            return Candidate::No;
        }
        if input.len() < 68 {
            return if input
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"+/-_".contains(b))
            {
                Candidate::Partial
            } else {
                Candidate::No
            };
        }
        return recognizable(input).map_or(Candidate::No, Candidate::Complete);
    }
    if !matches!(input[0], b'a' | b'%' | b'\\') {
        return Candidate::No;
    }
    let mut decoded = [0; DECODED_LEN];
    let mut position = 0;
    for index in 0..DECODED_LEN {
        let next = &input[position..];
        if next.is_empty() {
            return Candidate::Partial;
        }
        let (value, count) = if next[0] == b'%' {
            if next.len() < 3 {
                return if next[1..].iter().all(|b| hex(*b).is_some()) {
                    Candidate::Partial
                } else {
                    Candidate::No
                };
            }
            let (Some(high), Some(low)) = (hex(next[1]), hex(next[2])) else {
                return Candidate::No;
            };
            (high * 16 + low, 3)
        } else if next[0] == b'\\' {
            if next.len() < 4 {
                return if b"\\u00".starts_with(next) {
                    Candidate::Partial
                } else {
                    Candidate::No
                };
            }
            if !next.starts_with(b"\\u00") {
                return Candidate::No;
            }
            if next.len() < 6 {
                return if next[4..].iter().all(|b| hex(*b).is_some()) {
                    Candidate::Partial
                } else {
                    Candidate::No
                };
            }
            let (Some(high), Some(low)) = (hex(next[4]), hex(next[5])) else {
                return Candidate::No;
            };
            (high * 16 + low, 6)
        } else {
            (next[0], 1)
        };
        decoded[index] = value;
        if index < 8 {
            if ![b"aap_un1_", b"aap_pw1_", b"aap_cs1_"]
                .iter()
                .any(|prefix| prefix.starts_with(&decoded[..=index]))
            {
                return Candidate::No;
            }
        } else if !value.is_ascii_alphanumeric() && !b"_-".contains(&value) {
            return Candidate::No;
        }
        position += count;
    }
    if valid(&decoded) {
        Candidate::Complete(position)
    } else {
        Candidate::No
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_suppression_covers_every_boundary_and_single_byte_feeds() {
        for prefix in ["aap_un1_", "aap_pw1_", "aap_cs1_"] {
            let token = format!("{prefix}{}", aap_types::ids::random_id(32).unwrap());
            let variants = [
                token.clone(),
                token.replace("aap_", "%61ap_"),
                token.replace("aap_", "\\u0061ap_"),
                token.bytes().map(|b| format!("%{b:02X}")).collect(),
                token.bytes().map(|b| format!("\\u{b:04x}")).collect(),
                STANDARD.encode(&token),
                URL_SAFE.encode(&token),
            ];
            for encoded in variants {
                let input = format!("before:{encoded}:end");
                for split in 0..=input.len() {
                    let mut redactor = ImmediatePlaceholderRedactor::default();
                    let first = redactor.feed(&input.as_bytes()[..split], false).unwrap();
                    let last = redactor.feed(&input.as_bytes()[split..], true).unwrap();
                    let output = [first.as_ref(), last.as_ref()].concat();
                    assert_eq!(output, b"before:[redacted]:end", "split {split}: {encoded}");
                }
                let mut redactor = ImmediatePlaceholderRedactor::default();
                let mut bytes = Vec::new();
                for byte in input.bytes() {
                    let safe = redactor.feed(&[byte], false).unwrap();
                    assert!(safe.len() <= 10);
                    assert!(redactor.pending.len() <= 305);
                    bytes.extend(safe);
                }
                bytes.extend(redactor.feed(&[], true).unwrap());
                assert_eq!(bytes, b"before:[redacted]:end");
            }
        }
    }

    #[test]
    fn interactive_data_is_immediate_and_ambiguous_fragments_stay_hidden() {
        let mut redactor = ImmediatePlaceholderRedactor::default();
        let ordinary = b"ping\0\xff reply apply %ZZ \\x YQ!!";
        assert_eq!(redactor.feed(ordinary, false).unwrap(), ordinary.as_slice());
        assert_eq!(
            redactor.feed(b"aap_pw", false).unwrap(),
            b"[redacted]".as_slice()
        );
        // A later mismatch never restores already masked source bytes.
        assert_eq!(
            redactor.feed(b"!reply", false).unwrap(),
            b"!reply".as_slice()
        );
        assert_eq!(redactor.feed(b"a", true).unwrap(), b"[redacted]".as_slice());
        assert!(redactor.feed(b"later", false).is_err());
    }

    #[test]
    fn excessive_input_is_rejected_without_consuming_the_stream() {
        let mut redactor = ImmediatePlaceholderRedactor::default();
        assert!(redactor.feed(&vec![b'x'; 256 * 1024 + 1], false).is_err());
        assert_eq!(redactor.feed(b"ping", true).unwrap(), b"ping".as_slice());
    }
}
