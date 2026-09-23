//! Deliberately simple synthetic peer. Never a real authentication server.
use super::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::task::{JoinHandle, JoinSet};

pub const API_KEY: &str = "synthetic-demo-api-key";
pub const USER: &str = "synthetic-demo-user";
pub const PASSWORD: &str = "synthetic-demo-password";
const PRE: &str = "synthetic-demo-pre-cookie";
const COOKIE: &str = "synthetic-demo-session-cookie";
const CSRF: &str = "synthetic-demo-csrf";

pub fn clean(bytes: &[u8]) -> Result<()> {
    for value in [API_KEY, USER, PASSWORD, PRE, COOKIE, CSRF] {
        if bytes
            .windows(value.len())
            .any(|window| window == value.as_bytes())
        {
            return Err("synthetic credential escaped the proxy".into());
        }
    }
    Ok(())
}

pub struct Origin {
    pub address: SocketAddr,
    pub certificate: CertificateDer<'static>,
    pub receipts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Origin {
    pub fn url(&self) -> String {
        format!("https://demo.test:{}", self.address.port())
    }
    pub async fn start() -> Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec!["demo.test".into()])?;
        let certificate = certified.cert.der().clone();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
        )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let receipts = Arc::new(AtomicUsize::new(0));
        let counted = receipts.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    socket = listener.accept(), if connections.len() < 32 => {
                        let Ok((socket, _)) = socket else { return; };
                        let (acceptor, counted) = (acceptor.clone(), counted.clone());
                        connections.spawn(async move {
                            let run = async {
                                let stream = acceptor.accept(socket).await?;
                                let service = service_fn(move |request| respond(request, counted.clone()));
                                hyper::server::conn::http1::Builder::new().keep_alive(false)
                                    .serve_connection(TokioIo::new(stream), service).await?;
                                Result::<()>::Ok(())
                            };
                            let _ = tokio::time::timeout(Duration::from_secs(10), run).await;
                        });
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        Ok(Self {
            address,
            certificate,
            receipts,
            task,
        })
    }
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn respond(
    request: http::Request<Incoming>,
    receipts: Arc<AtomicUsize>,
) -> Result<http::Response<Full<Bytes>>> {
    receipts.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = request.into_parts();
    let body = Limited::new(body, 65536).collect().await?.to_bytes();
    let has_cookie = |name: &str, value: &str| {
        parts
            .headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|cookies| {
                cookies
                    .split(';')
                    .any(|field| field.trim() == format!("{name}={value}"))
            })
    };
    let mut response = http::Response::builder().header("content-type", "application/json");
    let value = match (parts.method.as_str(), parts.uri.path()) {
        ("POST", "/v1/chat/completions")
            if parts
                .headers
                .get("authorization")
                .is_some_and(|v| v == format!("Bearer {API_KEY}").as_str()) =>
        {
            json!({"id":"demo", "object":"chat.completion", "model":"demo",
                "choices":[{"index":0,"message":{"role":"assistant","content":"Hello through the credential proxy!"},"finish_reason":"stop"}],
                "credential_echo":API_KEY})
        }
        ("GET", "/login") => {
            response = response.header(
                "set-cookie",
                format!("pre={PRE}; Secure; HttpOnly; Path=/; SameSite=Strict"),
            );
            json!({"csrf":CSRF,"cookie_echo":PRE})
        }
        ("POST", "/session")
            if has_cookie("pre", PRE)
                && body == format!("user={USER}&password={PASSWORD}&csrf={CSRF}") =>
        {
            response = response.header(
                "set-cookie",
                format!("session={COOKIE}; Secure; HttpOnly; Path=/; SameSite=Strict"),
            );
            json!({"authenticated":true,"credential_echo":format!("{USER} {PASSWORD} {COOKIE}")})
        }
        ("GET", "/protected") if has_cookie("session", COOKIE) => {
            json!({"data":"demo protected resource","cookie_echo":COOKIE})
        }
        _ => {
            response = response.status(401);
            json!({"error":"demo authentication required"})
        }
    };
    Ok(response.body(Full::new(Bytes::from(serde_json::to_vec(&value)?)))?)
}
