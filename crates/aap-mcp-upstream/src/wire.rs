use aap_types::{ErrorCode, Result};
use serde_json::{Map, Value};
use std::io::Write;

pub(crate) fn decode(bytes: &[u8], limit: usize) -> Result<Value> {
    if bytes.len() > limit {
        return Err(ErrorCode::LimitExceeded.into());
    }
    // Scan structural amplification before allocating a Value tree. Escaped
    // delimiters inside strings cannot create nesting or bypass this bound.
    let (mut depth, mut tokens, mut string, mut escaped) = (0usize, 0usize, false, false);
    for byte in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                string = false;
            }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    tokens += 1;
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                b',' | b':' => tokens += 1,
                _ => {}
            }
            if depth > 64 || tokens > 32_768 {
                return Err(ErrorCode::LimitExceeded.into());
            }
        }
    }
    aap_types::json::decode(bytes).map_err(|_| ErrorCode::RequestInvalid.into())
}

pub(crate) fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(ErrorCode::RequestInvalid)?;
    if object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(ErrorCode::RequestInvalid.into());
    }
    Ok(object)
}

pub(crate) fn empty_meta(value: &Value) -> Result<()> {
    if value
        .get("_meta")
        .is_some_and(|meta| !meta.as_object().is_some_and(|object| object.is_empty()))
    {
        return Err(ErrorCode::AuthProfileUnsupported.into());
    }
    Ok(())
}

pub(crate) fn valid_id(value: &Value) -> bool {
    match value {
        Value::String(id) => !id.is_empty() && id.len() <= 128,
        Value::Number(id) => id
            .as_i64()
            .is_some_and(|id| (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&id)),
        _ => false,
    }
}

pub(crate) fn encode(value: &Value, limit: usize) -> Result<Vec<u8>> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit - self.bytes.len() {
                return Err(std::io::ErrorKind::FileTooLarge.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| ErrorCode::LimitExceeded)?;
    Ok(output.bytes)
}
