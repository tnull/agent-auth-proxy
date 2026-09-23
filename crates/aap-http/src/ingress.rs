use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::UnixStream,
    sync::Semaphore,
    time::Instant,
};

#[derive(Clone, Copy)]
pub(crate) struct RequestDeadline(pub Instant);
pub(crate) struct Prelude {
    pub bytes: Bytes,
    pub header_len: usize,
    stream: bool,
    control: bool,
}

pub(super) async fn serve(mut io: UnixStream, router: Router, work: Arc<Semaphore>) -> Result<()> {
    let started = Instant::now();
    if matches!(router, Router::Local(_)) {
        return tokio::time::timeout_at(
            started + Duration::from_secs(610),
            http(io, Bytes::new(), router, None),
        )
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    }
    let deadline = started + Duration::from_secs(10);
    let prelude = match tokio::time::timeout_at(deadline, read_prelude(&mut io)).await {
        Ok(Ok(value)) if Instant::now() < deadline => value,
        Ok(Err(failure)) => return error(&mut io, failure).await,
        _ => return error(&mut io, ErrorCode::RequestInvalid.into()).await,
    };
    // Work cannot occupy the four remaining bounded classification/control slots.
    // Hold the permit through response bodies, CONNECT, or the entire stream.
    let _work = if prelude.control {
        None
    } else {
        match work.try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return error(&mut io, ErrorCode::LimitExceeded.into()).await,
        }
    };
    if prelude.stream {
        let Router::Session(session, _) = router else {
            unreachable!()
        };
        // Approval and connected phases have distinct budgets, not the ordinary
        // HTTP response timer. The engine enforces its narrower authority bounds.
        return tokio::time::timeout_at(
            started + Duration::from_secs(922),
            stream::opening::serve(io, prelude, session, deadline),
        )
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    }
    tokio::time::timeout_at(
        started + Duration::from_secs(610),
        http(io, prelude.bytes, router, Some(deadline)),
    )
    .await
    .map_err(|_| ErrorCode::ResultUnavailable)?
}

pub(crate) async fn read_prelude(io: &mut UnixStream) -> Result<Prelude> {
    let mut bytes = Vec::with_capacity(16 * 1024);
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);
        let parsed = request
            .parse(&bytes)
            .map_err(|_| ErrorCode::RequestInvalid)?;
        let is_stream = request.path == Some(aap_types::stream::OPEN_PATH);
        let limit = if is_stream { 16 * 1024 } else { 64 * 1024 };
        if let httparse::Status::Complete(header_len) = parsed {
            if header_len > limit {
                return Err(ErrorCode::LimitExceeded.into());
            }
            let control = request.method == Some("POST")
                && request.version == Some(1)
                && matches!(request.path, Some(wire::STATUS | wire::CANCEL));
            return Ok(Prelude {
                bytes: Bytes::from(bytes),
                header_len,
                stream: is_stream,
                control,
            });
        }
        if bytes.len() >= limit {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let mut chunk = [0; 1024];
        let room = chunk.len().min(limit - bytes.len());
        let count = io
            .read(&mut chunk[..room])
            .await
            .map_err(|_| ErrorCode::RequestInvalid)?;
        if count == 0 {
            return Err(ErrorCode::RequestInvalid.into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

async fn http(
    io: UnixStream,
    prefix: Bytes,
    router: Router,
    deadline: Option<Instant>,
) -> Result<()> {
    let pending = Arc::new(std::sync::Mutex::new(None));
    let handoff = pending.clone();
    let service = service_fn(move |mut request: http::Request<Incoming>| {
        let router = router.clone();
        let pending = pending.clone();
        if let Some(deadline) = deadline {
            request.extensions_mut().insert(RequestDeadline(deadline));
        }
        async move {
            let response = match router {
                Router::Local(handler) => handler.handle(request).await,
                Router::Session(session, Some(identities))
                    if request.method() == http::Method::CONNECT =>
                {
                    proxy::admit(request, session, identities, pending)
                        .await
                        .unwrap_or_else(error_response)
                }
                Router::Session(session, _) => SessionHandler(session).handle(request).await,
            };
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let _ = http1_builder()
        .serve_connection(TokioIo::new(Replay { io, prefix }), service)
        .with_upgrades()
        .await;
    let upgrade = handoff.lock().map_err(|_| ErrorCode::InternalError)?.take();
    if let Some(upgrade) = upgrade {
        proxy::serve_tunnel(upgrade).await?;
    }
    Ok(())
}

struct Replay {
    io: UnixStream,
    prefix: Bytes,
}
impl AsyncRead for Replay {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let count = buffer.remaining().min(self.prefix.len());
            buffer.put_slice(&self.prefix[..count]);
            self.prefix = if count == self.prefix.len() {
                Bytes::new()
            } else {
                self.prefix.slice(count..)
            };
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Replay {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

pub(crate) async fn error(io: &mut UnixStream, error: Error) -> Result<()> {
    let response = error_response(error);
    let status = response.status();
    let bytes = Limited::new(response.into_body(), 8192)
        .collect()
        .await
        .map_err(|_| ErrorCode::InternalError)?
        .to_bytes();
    json(io, status, &bytes, "x-aap-error: 1\r\n").await
}
pub(crate) async fn json(
    io: &mut UnixStream,
    status: http::StatusCode,
    body: &[u8],
    tag: &'static str,
) -> Result<()> {
    if body.len() > 16 * 1024 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    let header = format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\n{tag}\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or(""),
        body.len()
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        io.write_all(header.as_bytes()).await?;
        io.write_all(body).await?;
        io.flush().await
    })
    .await
    .map_err(|_| ErrorCode::ResultUnavailable)?
    .map_err(|_| ErrorCode::ResultUnavailable.into())
}
