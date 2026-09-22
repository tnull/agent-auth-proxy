//! Session-bound HTTP ingress, without credential or independent policy access.
use aap_transport::Cancellation;
use aap_types::{AgentService, BoxFuture, Error, ErrorCode, Response, Result, wire};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{os::unix::net::UnixListener, sync::Arc, time::Duration};

/// A host-bound local router. Different authority planes need different listeners
/// and handler instances; caller headers never select a handler.
pub trait LocalHandler: Send + Sync {
    fn handle(&self, request: http::Request<Incoming>) -> BoxFuture<'_, Response>;
}

pub async fn serve_session(
    listener: UnixListener,
    session: Arc<dyn AgentService>,
    expected_uid: u32,
    shutdown: Cancellation,
) -> Result<()> {
    serve_local(
        listener,
        Arc::new(SessionHandler(session)),
        expected_uid,
        shutdown,
    )
    .await
}

pub async fn serve_local(
    listener: UnixListener,
    handler: Arc<dyn LocalHandler>,
    expected_uid: u32,
    shutdown: Cancellation,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .map_err(|_| ErrorCode::InternalError)?;
    let listener =
        tokio::net::UnixListener::from_std(listener).map_err(|_| ErrorCode::InternalError)?;
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept(), if connections.len() < 32 => {
                let (stream, _) = accepted.map_err(|_| ErrorCode::InternalError)?;
                if !stream.peer_cred().is_ok_and(|credentials| credentials.uid() == expected_uid) { continue; }
                let handler = handler.clone(); let cancelled = shutdown.clone();
                connections.spawn(async move {
                    let service = service_fn(move |request| { let handler = handler.clone(); async move {
                        Ok::<_, std::convert::Infallible>(handler.handle(request).await)
                    }});
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.keep_alive(false).max_headers(64).max_buf_size(64*1024).timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                    let connection = builder.serve_connection(TokioIo::new(stream), service);
                    tokio::select! { _ = cancelled.cancelled() => {}, _ = tokio::time::timeout(Duration::from_secs(610), connection) => {} }
                });
            },
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

struct SessionHandler(Arc<dyn AgentService>);
impl LocalHandler for SessionHandler {
    fn handle(&self, request: http::Request<Incoming>) -> BoxFuture<'_, Response> {
        Box::pin(async move {
            match self.dispatch(request).await {
                Ok(response) => response,
                Err(error) => error_response(error),
            }
        })
    }
}
impl SessionHandler {
    async fn dispatch(&self, request: http::Request<Incoming>) -> Result<Response> {
        validate_local_request(&request)?;
        let path = request.uri().path().to_owned();
        if ![
            wire::EXECUTE,
            wire::STATUS,
            wire::CANCEL,
            wire::SEARCH,
            wire::LOGIN,
            wire::AUTH_STATUS,
            wire::LOGOUT,
            wire::ADMIT_CONNECT,
        ]
        .contains(&path.as_str())
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let body = read_body(request).await?;
        match path.as_str() {
            wire::EXECUTE => self.0.execute(decode(&body)?).await,
            wire::STATUS => {
                let request: wire::RequestId = decode(&body)?;
                json_response(&self.0.request_status(request.request_id).await?)
            }
            wire::CANCEL => {
                let request: wire::RequestId = decode(&body)?;
                json_response(&self.0.cancel(request.request_id).await?)
            }
            wire::SEARCH => json_response(&self.0.search_items(decode(&body)?).await?),
            wire::LOGIN => json_response(&self.0.get_login(decode(&body)?).await?),
            wire::AUTH_STATUS => json_response(&self.0.auth_status(decode(&body)?).await?),
            wire::LOGOUT => json_response(&self.0.logout(decode(&body)?).await?),
            wire::ADMIT_CONNECT => {
                let request: wire::ConnectAuthority = decode(&body)?;
                self.0.admit_connect(request.authority).await?;
                json_response(&())
            }
            _ => Err(ErrorCode::PolicyDenied.into()),
        }
    }
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    aap_types::json::decode(body).map_err(|_| ErrorCode::RequestInvalid.into())
}

pub fn validate_local_request<B>(request: &http::Request<B>) -> Result<()> {
    if request.method() != http::Method::POST
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().query().is_some()
        || request.headers().get_all("host").iter().count() != 1
        || request
            .headers()
            .get("host")
            .is_none_or(|value| value != wire::HOST)
        || request.headers().get_all("content-type").iter().count() != 1
        || request
            .headers()
            .get("content-type")
            .is_none_or(|value| value != "application/json")
        || request.headers().len() > 64
        || request
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
            > 64 * 1024
        || request.headers().keys().any(|name| {
            !matches!(
                name.as_str(),
                "host"
                    | "content-type"
                    | "content-length"
                    | "transfer-encoding"
                    | "connection"
                    | "accept"
                    | "user-agent"
            )
        })
        || request
            .headers()
            .get("transfer-encoding")
            .is_some_and(|value| value != "chunked")
        || request
            .headers()
            .get("connection")
            .is_some_and(|value| value != "close" && value != "keep-alive")
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    Ok(())
}

pub async fn read_body(request: http::Request<Incoming>) -> Result<Bytes> {
    let collected = tokio::time::timeout(
        Duration::from_secs(10),
        Limited::new(request.into_body(), 2 * 1024 * 1024).collect(),
    )
    .await
    .map_err(|_| ErrorCode::RequestInvalid)?
    .map_err(|_| ErrorCode::LimitExceeded)?;
    if collected.trailers().is_some() {
        return Err(ErrorCode::RequestInvalid.into());
    }
    Ok(collected.to_bytes())
}

pub fn json_response<T: serde::Serialize>(value: &T) -> Result<Response> {
    let bytes = serde_json::to_vec(value).map_err(|_| ErrorCode::InternalError)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    http::Response::builder()
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(
            Full::new(Bytes::from(bytes))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .map_err(|_| ErrorCode::InternalError.into())
}
pub fn error_response(error: Error) -> Response {
    let status = match error.code {
        ErrorCode::SessionInvalid => 401,
        ErrorCode::PolicyDenied => 403,
        ErrorCode::RequestInvalid
        | ErrorCode::RequestConflict
        | ErrorCode::AuthProfileUnsupported
        | ErrorCode::PlaceholderInvalid => 400,
        ErrorCode::LimitExceeded => 429,
        _ => 503,
    };
    let mut response = json_response(&error).expect("fixed-size proxy error serializes");
    *response.status_mut() = http::StatusCode::from_u16(status).expect("constant status");
    response
        .headers_mut()
        .insert(wire::ERROR_HEADER, http::HeaderValue::from_static("1"));
    response
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
