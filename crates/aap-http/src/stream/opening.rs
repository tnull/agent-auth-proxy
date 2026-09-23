use crate::ingress::{self, Prelude};
use aap_types::{
    AgentService, ErrorCode, OperationState, Result,
    stream::{self, service::Admission},
};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::Instant,
};

pub(crate) fn validate(head: &[u8]) -> Result<usize> {
    if head.len() > 16 * 1024
        || !head.ends_with(b"\r\n\r\n")
        || head.iter().enumerate().any(|(i, byte)| {
            (*byte == b'\n' && (i == 0 || head[i - 1] != b'\r'))
                || (*byte == b'\r' && head.get(i + 1) != Some(&b'\n'))
        })
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let mut headers = [httparse::EMPTY_HEADER; 8];
    let mut request = httparse::Request::new(&mut headers);
    if request.parse(head).map_err(|_| ErrorCode::RequestInvalid)?
        != httparse::Status::Complete(head.len())
        || request.method != Some("POST")
        || request.path != Some(stream::OPEN_PATH)
        || request.version != Some(1)
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let mut length = None;
    let mut required = 0u8;
    for (index, header) in request.headers.iter().enumerate() {
        if request.headers[..index]
            .iter()
            .any(|previous| previous.name.eq_ignore_ascii_case(header.name))
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let value = header.value;
        match header.name.to_ascii_lowercase().as_str() {
            "host" if value == b"aap.local" => required |= 1,
            "connection" if value.eq_ignore_ascii_case(b"upgrade") => required |= 2,
            "upgrade" if value.eq_ignore_ascii_case(stream::PROTOCOL.as_bytes()) => required |= 4,
            "content-type" if value == b"application/json" => required |= 8,
            "content-length" if !value.is_empty() && value.iter().all(u8::is_ascii_digit) => {
                let parsed = std::str::from_utf8(value)
                    .map_err(|_| ErrorCode::RequestInvalid)?
                    .parse::<usize>()
                    .map_err(|_| ErrorCode::RequestInvalid)?;
                if parsed > stream::MAX_CONTROL_BYTES {
                    return Err(ErrorCode::RequestInvalid.into());
                }
                length = Some(parsed);
                required |= 16;
            }
            "user-agent" if value.len() <= 1024 => {}
            _ => return Err(ErrorCode::RequestInvalid.into()),
        }
    }
    if required != 31 {
        return Err(ErrorCode::RequestInvalid.into());
    }
    length.ok_or(ErrorCode::RequestInvalid.into())
}

pub(crate) async fn serve(
    mut io: UnixStream,
    prelude: Prelude,
    session: Arc<dyn AgentService>,
    deadline: Instant,
) -> Result<()> {
    let result =
        tokio::time::timeout_at(deadline, prepare(&mut io, prelude, &*session, deadline)).await;
    let (request, admission) = match result {
        Ok(Ok(value)) if Instant::now() < deadline => value,
        Ok(Err(error)) => return ingress::error(&mut io, error).await,
        _ => return ingress::error(&mut io, ErrorCode::RequestInvalid.into()).await,
    };
    match admission {
        Admission::Existing(status) => {
            let terminal = matches!(
                status.state,
                OperationState::Completed
                    | OperationState::Failed
                    | OperationState::OutcomeUnknown
                    | OperationState::Denied
                    | OperationState::Expired
                    | OperationState::Cancelled
            );
            let status_code = if terminal {
                http::StatusCode::OK
            } else {
                http::StatusCode::ACCEPTED
            };
            let bytes = serde_json::to_vec(&status).map_err(|_| ErrorCode::InternalError)?;
            ingress::json(
                &mut io,
                status_code,
                &bytes,
                "x-aap-operation-state: existing\r\n",
            )
            .await
        }
        Admission::New(pending) => {
            let abort = pending.abort_handle();
            tokio::select! {
                biased;
                _ = abort.terminated() => return Err(ErrorCode::ResultUnavailable.into()),
                result = tokio::time::timeout_at(deadline, io.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: aap-stream/1\r\n\r\n")) => {
                    result.map_err(|_| ErrorCode::ResultUnavailable)?.map_err(|_| ErrorCode::ResultUnavailable)?;
                },
            }
            super::serve_upgraded(io, request, pending)
                .await
                .map(|_| ())
        }
    }
}

async fn prepare(
    io: &mut UnixStream,
    prelude: Prelude,
    session: &dyn AgentService,
    deadline: Instant,
) -> Result<(stream::Open, Admission)> {
    if Instant::now() >= deadline {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let length = validate(&prelude.bytes[..prelude.header_len])?;
    let leading = &prelude.bytes[prelude.header_len..];
    if leading.len() > length {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let mut body = Vec::with_capacity(length);
    body.extend_from_slice(leading);
    drop(prelude);
    while body.len() < length {
        let mut chunk = [0; 1024];
        let room = chunk.len().min(length - body.len() + 1);
        let count = io
            .read(&mut chunk[..room])
            .await
            .map_err(|_| ErrorCode::RequestInvalid)?;
        if count == 0 || count > length - body.len() {
            return Err(ErrorCode::RequestInvalid.into());
        }
        body.extend_from_slice(&chunk[..count]);
    }
    // Inspect already readable trailing input before admission. Later arrivals
    // are watched continuously by serve_upgraded while approval/dialing waits.
    match io.try_read(&mut [0]) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        _ => return Err(ErrorCode::RequestInvalid.into()),
    }
    let request = stream::Open::decode(&body)?;
    if Instant::now() >= deadline {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let admission = session.open_stream(request.clone()).await?;
    Ok((request, admission))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn head() -> String {
        "POST /aap/v1/stream/open HTTP/1.1\r\nHost: aap.local\r\nConnection: upgrade\r\nUpgrade: aap-stream/1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n".into()
    }
    #[test]
    fn upgrade_headers_are_strict_before_http_normalization() {
        let valid = head();
        assert_eq!(validate(valid.as_bytes()).unwrap(), 2);
        assert_eq!(
            validate(
                valid
                    .replace("upgrade", "UpGrAdE")
                    .replace("aap-stream", "AAP-STREAM")
                    .as_bytes()
            )
            .unwrap(),
            2
        );
        for invalid in [
            valid.replace("POST ", "GET "),
            valid.replace("HTTP/1.1", "HTTP/1.0"),
            valid.replace("/stream/open", "/stream/open?x=1"),
            valid.replace("Host: aap.local", "Host: elsewhere"),
            valid.replace("aap-stream/1", "aap-stream/2"),
            valid.replace("Connection: upgrade", "Connection: upgrade, keep-alive"),
            valid.replace("application/json", "application/json; charset=utf-8"),
            valid.replace(
                "Content-Length: 2",
                "Content-Length: 2\r\nContent-Length: 2",
            ),
            valid.replace("Host: aap.local", "Host: aap.local\r\nhost: aap.local"),
            valid.replace("Content-Length: 2", "Content-Length: +2"),
            valid.replace("Content-Length: 2", "Content-Length: 16385"),
            valid.replace("Content-Length: 2\r\n", ""),
            valid.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n"),
            valid.replace("\r\n\r\n", "\r\nExpect: 100-continue\r\n\r\n"),
            valid.replace("\r\n\r\n", "\r\nUser-Agent: x\r\nUser-Agent: y\r\n\r\n"),
            valid.replace("\r\n", "\n"),
            valid.replace(
                "\r\n\r\n",
                &format!("\r\nUser-Agent: {}\r\n\r\n", "x".repeat(1025)),
            ),
        ] {
            assert!(
                validate(invalid.as_bytes()).is_err(),
                "accepted invalid opening: {invalid}"
            );
        }
    }
}
