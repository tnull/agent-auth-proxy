//! Verified network execution, without credential lookup or independent policy.

use aap_types::{BoxFuture, Error, ErrorCode, Response, Result};
use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::TcpStream,
    task::JoinHandle,
    time::{Instant, Sleep},
};

#[derive(Clone)]
pub struct Cancellation {
    sender: tokio::sync::watch::Sender<bool>,
}
impl Default for Cancellation {
    fn default() -> Self {
        Self {
            sender: tokio::sync::watch::channel(false).0,
        }
    }
}
impl Cancellation {
    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }
    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }
    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        let _ = receiver.wait_for(|value| *value).await;
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            total_timeout: Duration::from_secs(600),
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 32 * 1024 * 1024,
        }
    }
}

pub struct Endpoint {
    origin: http::Uri,
    address: SocketAddr,
}
impl Endpoint {
    pub fn new(origin: &str, address: SocketAddr) -> Result<Self> {
        let uri: http::Uri = origin.parse().map_err(|_| ErrorCode::RequestInvalid)?;
        let authority = uri.authority().ok_or(ErrorCode::RequestInvalid)?;
        if origin.len() > 4096
            || !origin.is_ascii()
            || origin.contains('#')
            || uri.scheme_str() != Some("https")
            || authority.as_str().contains('@')
            || authority.as_str().ends_with(':')
            || uri.host().is_none_or(str::is_empty)
            || (authority.as_str() != authority.host() && authority.port_u16().is_none())
            || uri.host().is_some_and(|host| host.ends_with('.'))
            || !matches!(uri.path(), "" | "/")
            || uri.query().is_some()
            || uri.port_u16().unwrap_or(443) != address.port()
            || address.port() == 0
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(Self {
            origin: uri,
            address,
        })
    }
}

pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>>;
}
pub struct SystemResolver {
    pub timeout: Duration,
}
impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            if host.is_empty()
                || host.len() > 253
                || !host.is_ascii()
                || port == 0
                || host
                    .bytes()
                    .any(|byte| !byte.is_ascii_alphanumeric() && !b".-:".contains(&byte))
                || self.timeout.is_zero()
                || self.timeout > Duration::from_secs(60)
            {
                return Err(ErrorCode::RequestInvalid.into());
            }
            let addresses =
                tokio::time::timeout(self.timeout, tokio::net::lookup_host((host, port)))
                    .await
                    .map_err(|_| ErrorCode::UpstreamUnavailable)?
                    .map_err(|_| ErrorCode::UpstreamUnavailable)?;
            let mut candidates = Vec::new();
            for address in addresses {
                if candidates.len() == 64 {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                candidates.push(address);
            }
            if candidates.is_empty() {
                return Err(ErrorCode::UpstreamUnavailable.into());
            }
            Ok(candidates)
        })
    }
}

pub trait Transport: Send + Sync {
    fn execute(
        &self,
        endpoint: Endpoint,
        request: http::Request<Bytes>,
        limits: Limits,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<Response>>;
}

pub struct HttpsTransport {
    configuration: Arc<rustls::ClientConfig>,
}
impl HttpsTransport {
    pub fn new(roots: impl IntoIterator<Item = CertificateDer<'static>>) -> Result<Self> {
        let mut store = rustls::RootCertStore::empty();
        for root in roots {
            store.add(root).map_err(|_| ErrorCode::RequestInvalid)?;
        }
        let mut configuration = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| ErrorCode::InternalError)?
        .with_root_certificates(store)
        .with_no_client_auth();
        configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
        configuration.enable_early_data = false;
        Ok(Self {
            configuration: Arc::new(configuration),
        })
    }
}
impl Transport for HttpsTransport {
    fn execute(
        &self,
        endpoint: Endpoint,
        mut request: http::Request<Bytes>,
        limits: Limits,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move {
            validate(&endpoint, &mut request, &limits)?;
            if cancellation.is_cancelled() {
                return Err(ErrorCode::UpstreamUnavailable.into());
            }
            let deadline = Instant::now() + limits.total_timeout;
            let establishment = async {
                let socket = TcpStream::connect(endpoint.address)
                    .await
                    .map_err(|_| ErrorCode::UpstreamUnavailable)?;
                let name = endpoint
                    .origin
                    .host()
                    .ok_or(ErrorCode::RequestInvalid)?
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                let name = rustls::pki_types::ServerName::try_from(name.to_owned())
                    .map_err(|_| ErrorCode::RequestInvalid)?;
                let stream = tokio_rustls::TlsConnector::from(self.configuration.clone())
                    .connect(name, socket)
                    .await
                    .map_err(|_| ErrorCode::UpstreamUnavailable)?;
                http1::Builder::new()
                    .max_headers(64)
                    .max_buf_size(64 * 1024)
                    .handshake::<_, Full<Bytes>>(TokioIo::new(stream))
                    .await
                    .map_err(|_| ErrorCode::UpstreamUnavailable)
            };
            let (mut sender, connection) = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(ErrorCode::UpstreamUnavailable.into()),
                result = tokio::time::timeout_at(deadline.min(Instant::now() + limits.connect_timeout), establishment) =>
                    result.map_err(|_| ErrorCode::UpstreamUnavailable)??,
            };
            let driver = Driver(tokio::spawn(async move {
                let _ = connection.await;
            }));
            let response = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(ErrorCode::OutcomeUnknown.into()),
                result = tokio::time::timeout_at(deadline.min(Instant::now() + limits.idle_timeout), sender.send_request(request.map(Full::new))) =>
                    result.map_err(|_| ErrorCode::OutcomeUnknown)?.map_err(|_| ErrorCode::OutcomeUnknown)?,
            };
            check_headers(response.headers())?;
            let (parts, incoming) = response.into_parts();
            let timer = Box::pin(tokio::time::sleep_until(
                deadline.min(Instant::now() + limits.idle_timeout),
            ));
            let body = ResponseBody {
                incoming,
                driver: Some(driver),
                remaining: limits.max_response_bytes,
                deadline,
                idle: limits.idle_timeout,
                timer,
                cancelled: Box::pin(async move { cancellation.cancelled().await }),
                done: false,
            };
            Ok(http::Response::from_parts(parts, body.boxed_unsync()))
        })
    }
}

fn check_headers(headers: &http::HeaderMap) -> Result<()> {
    if headers.len() > 64
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
            > 64 * 1024
    {
        return Err(ErrorCode::LimitExceeded.into());
    }
    Ok(())
}

fn validate(
    endpoint: &Endpoint,
    request: &mut http::Request<Bytes>,
    limits: &Limits,
) -> Result<()> {
    if [
        limits.connect_timeout,
        limits.idle_timeout,
        limits.total_timeout,
    ]
    .into_iter()
    .any(|limit| limit.is_zero() || limit > Duration::from_secs(3600))
        || limits.max_request_bytes == 0
        || limits.max_request_bytes > 128 * 1024 * 1024
        || limits.max_response_bytes == 0
        || limits.max_response_bytes > 128 * 1024 * 1024
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    if request.body().len() > limits.max_request_bytes {
        return Err(ErrorCode::LimitExceeded.into());
    }
    if request.uri().scheme_str() != Some("https")
        || request.uri().authority() != endpoint.origin.authority()
        || !matches!(
            request.version(),
            http::Version::HTTP_10 | http::Version::HTTP_11
        )
        || !matches!(
            request.method().as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        )
        || request.uri().to_string().len() > 16 * 1024
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    check_headers(request.headers())?;
    let authority = endpoint
        .origin
        .authority()
        .ok_or(ErrorCode::RequestInvalid)?
        .as_str();
    if request.headers().get_all("host").iter().count() > 1
        || request
            .headers()
            .get("host")
            .is_some_and(|value| value.as_bytes() != authority.as_bytes())
        || [
            "connection",
            "proxy-connection",
            "proxy-authorization",
            "transfer-encoding",
            "content-length",
            "upgrade",
            "te",
            "trailer",
            "expect",
        ]
        .into_iter()
        .any(|name| request.headers().contains_key(name))
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    request.headers_mut().insert(
        "host",
        authority.parse().map_err(|_| ErrorCode::RequestInvalid)?,
    );
    request
        .headers_mut()
        .insert("connection", http::HeaderValue::from_static("close"));
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .ok_or(ErrorCode::RequestInvalid)?
        .as_str()
        .parse()
        .map_err(|_| ErrorCode::RequestInvalid)?;
    *request.version_mut() = http::Version::HTTP_11;
    Ok(())
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ResponseBody {
    incoming: Incoming,
    driver: Option<Driver>,
    remaining: usize,
    deadline: Instant,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
    cancelled: BoxFuture<'static, ()>,
    done: bool,
}
impl ResponseBody {
    fn fail(&mut self, code: ErrorCode) -> Poll<Option<Result<Frame<Bytes>>>> {
        self.done = true;
        self.driver.take();
        Poll::Ready(Some(Err(code.into())))
    }
}
impl Body for ResponseBody {
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
        if this.cancelled.as_mut().poll(context).is_ready()
            || this.timer.as_mut().poll(context).is_ready()
        {
            return this.fail(ErrorCode::OutcomeUnknown);
        }
        match Pin::new(&mut this.incoming).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if data.len() > this.remaining {
                        return this.fail(ErrorCode::LimitExceeded);
                    }
                    this.remaining -= data.len();
                    if !data.is_empty() {
                        this.timer
                            .as_mut()
                            .reset(this.deadline.min(Instant::now() + this.idle));
                    }
                }
                if frame
                    .trailers_ref()
                    .is_some_and(|headers| check_headers(headers).is_err())
                {
                    return this.fail(ErrorCode::LimitExceeded);
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

#[cfg(test)]
mod tests;
