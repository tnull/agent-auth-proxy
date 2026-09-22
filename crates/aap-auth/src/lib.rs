//! Private authentication transformations; no independent network access.
use aap_secrets::{Field, Snapshot};
use aap_types::{ErrorCode, Response, Result};
use base64::Engine;
use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

pub struct PreparedKey {
    value: http::HeaderValue,
    redactor: Redactor,
}
impl PreparedKey {
    pub fn new(snapshot: &Snapshot, prefix: &str) -> Result<Self> {
        let key = snapshot.field(Field::ApiKey)?.expose();
        if key.len() > 4096 || prefix.len() > 128 || !prefix.is_ascii() {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        let mut value = prefix.as_bytes().to_vec();
        value.extend_from_slice(key);
        let mut value = http::HeaderValue::from_bytes(&value).map_err(|_| ErrorCode::AuthFailed)?;
        value.set_sensitive(true);
        Ok(Self {
            value,
            redactor: Redactor::new(&[key])?,
        })
    }
    pub fn inject(self, request: &mut http::Request<Bytes>, header: &str) -> Result<Redactor> {
        let name = http::HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| ErrorCode::RequestInvalid)?;
        if request.headers().contains_key(&name) {
            return Err(ErrorCode::PolicyDenied.into());
        }
        request.headers_mut().insert(name, self.value);
        Ok(self.redactor)
    }
}

pub struct Redactor {
    patterns: Vec<Vec<u8>>,
    pending: Vec<u8>,
    longest: usize,
    done: bool,
}
impl Redactor {
    pub fn new(values: &[&[u8]]) -> Result<Self> {
        if values.len() > 16
            || values
                .iter()
                .any(|value| value.is_empty() || value.len() > 4096)
        {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let mut patterns = Vec::new();
        for value in values {
            patterns.push(value.to_vec());
            for engine in [
                base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::STANDARD_NO_PAD,
                base64::engine::general_purpose::URL_SAFE,
                base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ] {
                patterns.push(engine.encode(value).into_bytes());
            }
            for uppercase in [false, true] {
                let hex = if uppercase {
                    b"0123456789ABCDEF"
                } else {
                    b"0123456789abcdef"
                };
                let mut percent = Vec::new();
                let mut form = Vec::new();
                for byte in *value {
                    if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
                        percent.push(*byte);
                        form.push(*byte);
                    } else {
                        let encoded = [b'%', hex[(byte >> 4) as usize], hex[(byte & 15) as usize]];
                        percent.extend(encoded);
                        if *byte == b' ' {
                            form.push(b'+');
                        } else {
                            form.extend(encoded);
                        }
                    }
                }
                patterns.push(percent);
                patterns.push(form);
            }
            if let Ok(text) = std::str::from_utf8(value) {
                let json = serde_json::to_vec(text).map_err(|_| ErrorCode::InternalError)?;
                patterns.push(json[1..json.len() - 1].to_vec());
            }
        }
        patterns.sort();
        patterns.dedup();
        patterns.sort_by_key(|value| std::cmp::Reverse(value.len()));
        if patterns.iter().map(Vec::len).sum::<usize>() > 1024 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let longest = patterns.first().map_or(1, Vec::len);
        Ok(Self {
            patterns,
            pending: Vec::new(),
            longest,
            done: false,
        })
    }
    pub fn feed(&mut self, chunk: &[u8], end: bool) -> Result<Bytes> {
        if self.done || chunk.len() > 256 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        self.pending.extend_from_slice(chunk);
        let mut output = Vec::new();
        let mut position = 0;
        while position < self.pending.len()
            && (end || self.pending.len() - position >= self.longest)
        {
            if let Some(pattern) = self
                .patterns
                .iter()
                .find(|pattern| self.pending[position..].starts_with(pattern))
            {
                output.extend_from_slice(b"[redacted]");
                position += pattern.len();
            } else {
                output.push(self.pending[position]);
                position += 1;
            }
        }
        self.pending.drain(..position);
        self.done = end;
        Ok(output.into())
    }
}
pub fn sanitize_response(response: Response, mut redactor: Redactor) -> Result<Response> {
    if response.status().is_redirection()
        || response.status().is_informational()
        || response.headers().get_all("content-type").iter().count() != 1
        || response
            .headers()
            .get_all("content-encoding")
            .iter()
            .count()
            > 1
        || response
            .headers()
            .get("content-encoding")
            .is_some_and(|value| value != "identity")
    {
        return Err(ErrorCode::InspectionUnavailable.into());
    }
    let media = response.headers()["content-type"]
        .to_str()
        .map_err(|_| ErrorCode::InspectionUnavailable)?
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let media = match media {
        "application/json" => "application/json",
        "text/event-stream" => "text/event-stream",
        "text/plain" => "text/plain",
        _ => return Err(ErrorCode::InspectionUnavailable.into()),
    };
    let mut cookies = Vec::new();
    for header in response.headers().get_all("set-cookie") {
        if cookies.len() == 16 || header.as_bytes().len() > 8192 {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        let pair = header
            .to_str()
            .map_err(|_| ErrorCode::InspectionUnavailable)?
            .split(';')
            .next()
            .ok_or(ErrorCode::InspectionUnavailable)?;
        let (name, value) = pair
            .split_once('=')
            .ok_or(ErrorCode::InspectionUnavailable)?;
        if http::HeaderName::from_bytes(name.trim().as_bytes()).is_err() {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        let value = value.trim();
        let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if value.bytes().any(|byte| {
            !(0x21..=0x7e).contains(&byte) || matches!(byte, b'"' | b',' | b';' | b'\\')
        }) {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        if !value.is_empty() {
            cookies.push(value.as_bytes());
        }
    }
    let cookie_redactor = Redactor::new(&cookies)?;
    redactor.patterns.extend(cookie_redactor.patterns);
    redactor.patterns.sort();
    redactor.patterns.dedup();
    redactor
        .patterns
        .sort_by_key(|value| std::cmp::Reverse(value.len()));
    if redactor.patterns.iter().map(Vec::len).sum::<usize>() > 1024 * 1024 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    redactor.longest = redactor.patterns.first().map_or(1, Vec::len);
    let (parts, body) = response.into_parts();
    http::Response::builder()
        .status(parts.status)
        .header("content-type", media)
        .body(
            Sanitized {
                body,
                redactor,
                done: false,
            }
            .boxed_unsync(),
        )
        .map_err(|_| ErrorCode::InternalError.into())
}

struct Sanitized {
    body: aap_types::Body,
    redactor: Redactor,
    done: bool,
}
impl Body for Sanitized {
    type Data = Bytes;
    type Error = aap_types::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        for _ in 0..32 {
            let (chunk, end) = match Pin::new(&mut this.body).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => (data, false),
                    Err(_) => continue,
                },
                Poll::Ready(Some(Err(error))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    this.done = true;
                    (Bytes::new(), true)
                }
                Poll::Pending => return Poll::Pending,
            };
            match this.redactor.feed(&chunk, end) {
                Ok(bytes) if !bytes.is_empty() => return Poll::Ready(Some(Ok(Frame::data(bytes)))),
                Ok(_) if end => return Poll::Ready(None),
                Ok(_) => {}
                Err(error) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aap_secrets::{ItemMetadata, Lease, SecretBytes, Version};
    use http_body_util::{BodyExt, Full};
    fn snapshot() -> Snapshot {
        Snapshot::new(
            ItemMetadata {
                lease: Lease {
                    version: Version::fresh().unwrap(),
                    generation: Version::fresh().unwrap(),
                },
                fields: vec![Field::ApiKey],
                valid_until: None,
            },
            [(
                Field::ApiKey,
                SecretBytes::new(b"synthetic-api-key".to_vec()).unwrap(),
            )]
            .into(),
        )
        .unwrap()
    }
    #[test]
    fn prepares_a_private_header_and_redacts_split_echoes() {
        let mut request = http::Request::new(Bytes::new());
        let mut redactor = PreparedKey::new(&snapshot(), "Bearer ")
            .expect("key preparation failed")
            .inject(&mut request, "authorization")
            .unwrap();
        assert_eq!(
            request.headers()["authorization"],
            "Bearer synthetic-api-key"
        );
        let mut output = Vec::new();
        output.extend(redactor.feed(b"prefix synthetic-", false).unwrap());
        output.extend(redactor.feed(b"api-key suffix", true).unwrap());
        assert_eq!(output, b"prefix [redacted] suffix");
    }
    #[test]
    fn every_chunk_boundary_and_common_encodings_are_suppressed() {
        use base64::Engine;
        let secret = b"a&b\"c";
        let json = serde_json::to_string(std::str::from_utf8(secret).unwrap()).unwrap();
        for echo in [
            secret.to_vec(),
            b"a%26b%22c".to_vec(),
            json.as_bytes()[1..json.len() - 1].to_vec(),
            base64::engine::general_purpose::STANDARD
                .encode(secret)
                .into_bytes(),
        ] {
            for split in 0..=echo.len() {
                let mut redactor =
                    Redactor::new(&[secret]).expect("redactor initialization failed");
                let mut output = redactor.feed(&echo[..split], false).unwrap().to_vec();
                output.extend(redactor.feed(&echo[split..], true).unwrap());
                assert_eq!(output, b"[redacted]");
            }
        }
    }
    #[tokio::test]
    async fn response_boundary_strips_private_headers_and_rejects_encodings() {
        let response = || {
            http::Response::builder()
                .header("content-type", "application/json")
                .header("set-cookie", "session=synthetic-cookie")
                .header("x-secret-echo", "synthetic-api-key")
                .header("content-length", "19")
                .body(
                    Full::new(Bytes::from_static(b"\"synthetic-api-key\""))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap()
        };
        let safe = sanitize_response(response(), Redactor::new(&[b"synthetic-api-key"]).unwrap())
            .expect("supported response refused");
        assert_eq!(safe.headers().len(), 1);
        assert_eq!(
            safe.into_body().collect().await.unwrap().to_bytes(),
            "\"[redacted]\""
        );
        let mut compressed = response();
        compressed
            .headers_mut()
            .insert("content-encoding", http::HeaderValue::from_static("gzip"));
        assert!(sanitize_response(compressed, Redactor::new(&[]).unwrap()).is_err());
        let mut redirect = response();
        *redirect.status_mut() = http::StatusCode::TEMPORARY_REDIRECT;
        assert!(sanitize_response(redirect, Redactor::new(&[]).unwrap()).is_err());
    }

    #[tokio::test]
    async fn captured_cookie_values_are_also_suppressed_from_the_response_body() {
        let response = http::Response::builder()
            .header("content-type", "text/plain")
            .header(
                "set-cookie",
                "session=new-private-cookie; Secure; HttpOnly; Path=/",
            )
            .body(
                Full::new(Bytes::from_static(b"echo new-private-cookie"))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let safe = sanitize_response(response, Redactor::new(&[]).unwrap()).unwrap();
        assert_eq!(
            safe.into_body().collect().await.unwrap().to_bytes(),
            "echo [redacted]",
            "new cookie escaped via the body"
        );
    }
}
