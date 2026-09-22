//! Agent-safe local client without any credential-custody dependency.
use aap_types::*;
use bytes::Bytes;
use http_body::{Body as BodyTrait, Frame};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

#[derive(Clone)]
pub struct DaemonSessionClient {
    path: PathBuf,
}
impl DaemonSessionClient {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
    async fn call(&self, path: &str, bytes: Vec<u8>) -> Result<Response> {
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::UnixStream::connect(&self.path),
        )
        .await
        .map_err(|_| ErrorCode::SessionInvalid)?
        .map_err(|_| ErrorCode::SessionInvalid)?;
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(64)
            .max_buf_size(64 * 1024)
            .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
            .await
            .map_err(|_| ErrorCode::SessionInvalid)?;
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let request = http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", wire::HOST)
            .header("content-type", "application/json")
            .header("connection", "close")
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|_| ErrorCode::RequestInvalid)?;
        let deadline = Instant::now() + Duration::from_secs(630);
        let response = tokio::time::timeout_at(deadline, sender.send_request(request))
            .await
            .map_err(|_| ErrorCode::OutcomeUnknown)?
            .map_err(|_| ErrorCode::OutcomeUnknown)?;
        let (parts, incoming) = response.into_parts();
        let body = ClientBody {
            incoming,
            driver: Some(driver),
            remaining: 32 * 1024 * 1024,
            deadline,
            timer: Box::pin(tokio::time::sleep_until(
                deadline.min(Instant::now() + Duration::from_secs(65)),
            )),
            done: false,
        }
        .boxed_unsync();
        let response = http::Response::from_parts(parts, body);
        if response.headers().contains_key(wire::ERROR_HEADER) {
            if response
                .headers()
                .get_all(wire::ERROR_HEADER)
                .iter()
                .count()
                != 1
                || response.headers()[wire::ERROR_HEADER] != "1"
            {
                return Err(ErrorCode::OutcomeUnknown.into());
            }
            let bytes = Limited::new(response.into_body(), 8192)
                .collect()
                .await
                .map_err(|_| ErrorCode::OutcomeUnknown)?
                .to_bytes();
            let error: Error =
                aap_types::json::decode(&bytes).map_err(|_| ErrorCode::OutcomeUnknown)?;
            return Err(error);
        }
        Ok(response)
    }
    async fn json<T: serde::Serialize + Sync, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        value: &T,
    ) -> Result<R> {
        let response = self
            .call(
                path,
                serde_json::to_vec(value).map_err(|_| ErrorCode::RequestInvalid)?,
            )
            .await?;
        if response.status() != http::StatusCode::OK {
            return Err(ErrorCode::OutcomeUnknown.into());
        }
        let bytes = Limited::new(response.into_body(), 2 * 1024 * 1024)
            .collect()
            .await
            .map_err(|_| ErrorCode::ResultUnavailable)?
            .to_bytes();
        aap_types::json::decode(&bytes).map_err(|_| ErrorCode::ResultUnavailable.into())
    }
}
impl AgentService for DaemonSessionClient {
    fn execute(&self, request: ExecuteRequest) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move {
            self.call(
                wire::EXECUTE,
                serde_json::to_vec(&request).map_err(|_| ErrorCode::RequestInvalid)?,
            )
            .await
        })
    }
    fn search_items(&self, request: SearchItems) -> BoxFuture<'_, Result<SearchResult>> {
        Box::pin(async move { self.json(wire::SEARCH, &request).await })
    }
    fn get_login(&self, request: GetLogin) -> BoxFuture<'_, Result<Login>> {
        Box::pin(async move { self.json(wire::LOGIN, &request).await })
    }
    fn auth_status(&self, request: AuthContext) -> BoxFuture<'_, Result<AuthStatus>> {
        Box::pin(async move { self.json(wire::AUTH_STATUS, &request).await })
    }
    fn logout(&self, request: AuthContext) -> BoxFuture<'_, Result<Logout>> {
        Box::pin(async move { self.json(wire::LOGOUT, &request).await })
    }
    fn request_status(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>> {
        Box::pin(async move {
            self.json(wire::STATUS, &wire::RequestId { request_id })
                .await
        })
    }
    fn cancel(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>> {
        Box::pin(async move {
            self.json(wire::CANCEL, &wire::RequestId { request_id })
                .await
        })
    }
    fn admit_connect(&self, authority: String) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.json(wire::ADMIT_CONNECT, &wire::ConnectAuthority { authority })
                .await
        })
    }
}

struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct ClientBody {
    incoming: Incoming,
    driver: Option<Driver>,
    remaining: usize,
    deadline: Instant,
    timer: Pin<Box<Sleep>>,
    done: bool,
}
impl ClientBody {
    fn fail(&mut self, code: ErrorCode) -> Poll<Option<Result<Frame<Bytes>>>> {
        self.done = true;
        self.driver.take();
        Poll::Ready(Some(Err(code.into())))
    }
}
impl BodyTrait for ClientBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if this.timer.as_mut().poll(context).is_ready() {
            return this.fail(ErrorCode::OutcomeUnknown);
        }
        match Pin::new(&mut this.incoming).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    if bytes.len() > this.remaining {
                        return this.fail(ErrorCode::LimitExceeded);
                    }
                    this.remaining -= bytes.len();
                    if !bytes.is_empty() {
                        this.timer
                            .as_mut()
                            .reset(this.deadline.min(Instant::now() + Duration::from_secs(65)));
                    }
                }
                if frame.trailers_ref().is_some() {
                    return this.fail(ErrorCode::InspectionUnavailable);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(_))) => this.fail(ErrorCode::OutcomeUnknown),
            Poll::Ready(None) => {
                this.done = true;
                this.driver.take();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
}
