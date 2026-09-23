use super::*;
use aap_types::{Error, OperationState, OperationStatus};
use std::path::Path;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

pub(crate) async fn open(path: &Path, request: stream::Open) -> Result<Admission> {
    request.validate()?;
    let id = request.request_id.clone();
    open_once(path, request)
        .await
        .map_err(|error| error.for_request(&id))
}

async fn open_once(path: &Path, request: stream::Open) -> Result<Admission> {
    let mut io = tokio::time::timeout(Duration::from_secs(10), UnixStream::connect(path))
        .await
        .map_err(|_| ErrorCode::SessionInvalid)?
        .map_err(|_| ErrorCode::SessionInvalid)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let (response, trailing) = tokio::time::timeout_at(deadline, async {
        let body = serde_json::to_vec(&request).map_err(|_| ErrorCode::RequestInvalid)?;
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: aap.local\r\nConnection: upgrade\r\nUpgrade: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            stream::OPEN_PATH, stream::PROTOCOL, body.len()
        );
        io.write_all(head.as_bytes()).await.map_err(|_| ErrorCode::ResultUnavailable)?;
        io.write_all(&body).await.map_err(|_| ErrorCode::ResultUnavailable)?;
        let mut bytes = Vec::with_capacity(16 * 1024);
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut response = httparse::Response::new(&mut headers);
            if let httparse::Status::Complete(length) = response.parse(&bytes).map_err(|_| ErrorCode::ResultUnavailable)? {
                let response = validate(&bytes[..length])?;
                return Ok::<_, aap_types::Error>((response, Bytes::copy_from_slice(&bytes[length..])));
            }
            if bytes.len() >= 16 * 1024 { return Err(ErrorCode::LimitExceeded.into()); }
            let mut chunk = [0; 1024];
            let room = chunk.len().min(16 * 1024 - bytes.len());
            let count = io.read(&mut chunk[..room]).await.map_err(|_| ErrorCode::ResultUnavailable)?;
            if count == 0 { return Err(ErrorCode::ResultUnavailable.into()); }
            bytes.extend_from_slice(&chunk[..count]);
        }
    }).await.map_err(|_| ErrorCode::ResultUnavailable)??;
    if Instant::now() >= deadline {
        return Err(ErrorCode::ResultUnavailable.into());
    }
    match response {
        Response::Upgrade => Ok(Admission::New(Box::new(Pending(Owner::new(
            Box::new(io),
            request,
            trailing,
        )?)))),
        Response::Json {
            length,
            status,
            existing,
        } => {
            let body = tokio::time::timeout_at(deadline, async {
                if trailing.len() > length {
                    return Err(ErrorCode::ResultUnavailable.into());
                }
                let mut bytes = Vec::with_capacity(length);
                bytes.extend_from_slice(&trailing);
                io.take((length - bytes.len() + 1) as u64)
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(|_| ErrorCode::ResultUnavailable)?;
                if bytes.len() != length {
                    return Err(ErrorCode::ResultUnavailable.into());
                }
                Ok::<_, aap_types::Error>(bytes)
            })
            .await
            .map_err(|_| ErrorCode::ResultUnavailable)??;
            if Instant::now() >= deadline {
                return Err(ErrorCode::ResultUnavailable.into());
            }
            if existing {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Existing {
                    request_id: String,
                    state: OperationState,
                    status: (),
                }
                let value: Existing =
                    aap_types::json::decode(&body).map_err(|_| ErrorCode::ResultUnavailable)?;
                let () = value.status;
                let terminal = matches!(
                    value.state,
                    OperationState::Completed
                        | OperationState::Failed
                        | OperationState::OutcomeUnknown
                        | OperationState::Denied
                        | OperationState::Expired
                        | OperationState::Cancelled
                );
                if value.request_id != request.request_id
                    || status != if terminal { 200 } else { 202 }
                {
                    return Err(ErrorCode::ResultUnavailable.into());
                }
                Ok(Admission::Existing(OperationStatus {
                    request_id: value.request_id,
                    state: value.state,
                    status: None,
                }))
            } else {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Failure {
                    code: ErrorCode,
                    request_id: Option<String>,
                }
                let failure: Failure =
                    aap_types::json::decode(&body).map_err(|_| ErrorCode::ResultUnavailable)?;
                let expected = match failure.code {
                    ErrorCode::SessionInvalid => 401,
                    ErrorCode::PolicyDenied => 403,
                    ErrorCode::RequestInvalid
                    | ErrorCode::RequestConflict
                    | ErrorCode::AuthProfileUnsupported
                    | ErrorCode::PlaceholderInvalid => 400,
                    ErrorCode::LimitExceeded => 429,
                    _ => 503,
                };
                if status != expected
                    || failure
                        .request_id
                        .as_ref()
                        .is_some_and(|id| id != &request.request_id)
                {
                    return Err(ErrorCode::ResultUnavailable.into());
                }
                Err(Error::new(failure.code))
            }
        }
    }
}

enum Response {
    Upgrade,
    Json {
        length: usize,
        status: u16,
        existing: bool,
    },
}

fn validate(head: &[u8]) -> Result<Response> {
    if head.len() > 16 * 1024
        || !head.ends_with(b"\r\n\r\n")
        || head.iter().enumerate().any(|(i, byte)| {
            (*byte == b'\n' && (i == 0 || head[i - 1] != b'\r'))
                || (*byte == b'\r' && head.get(i + 1) != Some(&b'\n'))
        })
    {
        return Err(ErrorCode::ResultUnavailable.into());
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    if response
        .parse(head)
        .map_err(|_| ErrorCode::ResultUnavailable)?
        != httparse::Status::Complete(head.len())
        || response.version != Some(1)
    {
        return Err(ErrorCode::ResultUnavailable.into());
    }
    let mut connection = None;
    let mut upgrade = None;
    let mut content_type = None;
    let mut length = None;
    let mut existing = false;
    let mut error = false;
    for (index, header) in response.headers.iter().enumerate() {
        if response.headers[..index]
            .iter()
            .any(|old| old.name.eq_ignore_ascii_case(header.name))
        {
            return Err(ErrorCode::ResultUnavailable.into());
        }
        match header.name.to_ascii_lowercase().as_str() {
            "connection" => connection = Some(header.value),
            "upgrade" => upgrade = Some(header.value),
            "content-type" => content_type = Some(header.value),
            "content-length"
                if !header.value.is_empty() && header.value.iter().all(u8::is_ascii_digit) =>
            {
                let count = std::str::from_utf8(header.value)
                    .map_err(|_| ErrorCode::ResultUnavailable)?
                    .parse::<usize>()
                    .map_err(|_| ErrorCode::ResultUnavailable)?;
                if count > 16 * 1024 {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                length = Some(count);
            }
            "x-aap-operation-state" if header.value == b"existing" => existing = true,
            "x-aap-error" if header.value == b"1" => error = true,
            "date" | "cache-control" => {}
            _ => return Err(ErrorCode::ResultUnavailable.into()),
        }
    }
    let status = response.code.ok_or(ErrorCode::ResultUnavailable)?;
    if status == 101 {
        if !connection.is_some_and(|value| value.eq_ignore_ascii_case(b"upgrade"))
            || !upgrade.is_some_and(|value| value.eq_ignore_ascii_case(stream::PROTOCOL.as_bytes()))
            || length.is_some()
            || content_type.is_some()
            || existing
            || error
        {
            return Err(ErrorCode::ResultUnavailable.into());
        }
        Ok(Response::Upgrade)
    } else {
        if !connection.is_some_and(|value| value.eq_ignore_ascii_case(b"close"))
            || content_type != Some(b"application/json")
            || upgrade.is_some()
            || existing == error
            || !(if existing {
                matches!(status, 200 | 202)
            } else {
                matches!(status, 400 | 401 | 403 | 429 | 503)
            })
        {
            return Err(ErrorCode::ResultUnavailable.into());
        }
        Ok(Response::Json {
            length: length.ok_or(ErrorCode::ResultUnavailable)?,
            status,
            existing,
        })
    }
}
