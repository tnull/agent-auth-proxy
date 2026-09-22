//! Synthetic test origins only. Production packages use this as a dev-dependency.

use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Limited};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
    time::Sleep,
};

#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub chunks: Vec<Bytes>,
    pub delay: Duration,
    pub disconnect: bool,
}

impl Reply {
    pub fn body(bytes: impl Into<Bytes>) -> Self {
        Self {
            status: 200,
            headers: vec![],
            chunks: vec![bytes.into()],
            delay: Duration::ZERO,
            disconnect: false,
        }
    }
}

pub struct Captured {
    pub method: http::Method,
    pub target: http::Uri,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

pub struct Origin {
    pub address: SocketAddr,
    pub certificate: CertificateDer<'static>,
    pub requests: Arc<Mutex<Vec<Captured>>>,
    task: JoinHandle<()>,
}

impl Origin {
    pub async fn spawn(reply: Reply) -> Self {
        Self::with_handler(move |_| reply.clone()).await
    }

    pub async fn with_handler(
        handler: impl Fn(&Captured) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["fixture.test".into()]).unwrap();
        let certificate = certified.cert.der().clone();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let records = requests.clone();
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept(), if connections.len() < 64 => {
                        let Ok((socket, _)) = accepted else { break; };
                        let (acceptor, records, handler) = (acceptor.clone(), records.clone(), handler.clone());
                        connections.spawn(async move {
                            let Ok(stream) = acceptor.accept(socket).await else { return; };
                            let service = service_fn(move |request: http::Request<Incoming>| {
                                let (records, handler) = (records.clone(), handler.clone());
                                async move {
                                    let (parts, body) = request.into_parts();
                                    let body = Limited::new(body, 1024 * 1024).collect().await.map_err(|_| std::io::Error::other("fixture body limit"))?.to_bytes();
                                    let captured = Captured { method: parts.method, target: parts.uri, headers: parts.headers, body };
                                    let reply = handler(&captured);
                                    records.lock().unwrap().push(captured);
                                    if reply.disconnect { return Err(std::io::Error::other("synthetic disconnect")); }
                                    let mut response = http::Response::builder().status(reply.status);
                                    for (name, value) in reply.headers { response = response.header(name, value); }
                                    Ok::<_, std::io::Error>(response.body(Chunks::new(reply.chunks, reply.delay)).unwrap())
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(stream), service).await;
                        });
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        Self {
            address,
            certificate,
            requests,
            task,
        }
    }

    pub fn origin(&self) -> String {
        format!("https://fixture.test:{}", self.address.port())
    }
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Chunks {
    chunks: VecDeque<Bytes>,
    delay: Duration,
    timer: Pin<Box<Sleep>>,
}
impl Chunks {
    fn new(chunks: Vec<Bytes>, delay: Duration) -> Self {
        Self {
            chunks: chunks.into(),
            delay,
            timer: Box::pin(tokio::time::sleep(delay)),
        }
    }
}
impl Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if this.chunks.is_empty() {
            return Poll::Ready(None);
        }
        if this.timer.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        this.timer
            .as_mut()
            .reset(tokio::time::Instant::now() + this.delay);
        Poll::Ready(this.chunks.pop_front().map(|chunk| Ok(Frame::data(chunk))))
    }
}
