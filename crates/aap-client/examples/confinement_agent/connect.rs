use aap_types::{ErrorCode, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bounded synthetic request and public trust root, never a private CA key.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub authority: String,
    pub server_name: String,
    pub root_der: Vec<u8>,
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// This client has no direct-network fallback, ambient roots, retry, redirect,
/// or private credential input. The caller bounds the entire action to five seconds.
pub async fn run(session: PathBuf, request: Request) -> Result<Value> {
    let authority = aap_types::proxy::ConnectAuthority::parse(&request.authority)?;
    if request.root_der.len() > 16 * 1024
        || request.body.len() > 16 * 1024
        || request.headers.len() > 64
        || request.path.len() > 2048
        || !request.path.starts_with('/')
        || request.host.len() > 512
        || request.server_name.len() > 253
        || request
            .headers
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
            > 8192
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let mut upstream = http::Request::builder()
        .method(request.method.as_str())
        .uri(&request.path)
        .header("host", &request.host)
        .header("connection", "close");
    for (name, value) in &request.headers {
        if ["host", "connection", "content-length", "transfer-encoding"]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        upstream = upstream.header(name, value);
    }
    let upstream = upstream
        .body(Full::new(Bytes::from(request.body)))
        .map_err(|_| ErrorCode::RequestInvalid)?;
    let name = ServerName::try_from(request.server_name).map_err(|_| ErrorCode::RequestInvalid)?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(request.root_der))
        .map_err(|_| ErrorCode::RequestInvalid)?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ErrorCode::InternalError)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut io = tokio::net::UnixStream::connect(session)
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    let authority = authority.authority();
    io.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    let mut head = vec![];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        head.push(
            io.read_u8()
                .await
                .map_err(|_| ErrorCode::ResultUnavailable)?,
        );
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    if response
        .parse(&head)
        .map_err(|_| ErrorCode::ResultUnavailable)?
        != httparse::Status::Complete(head.len())
        || response.version != Some(1)
    {
        return Err(ErrorCode::ResultUnavailable.into());
    }
    let status = response.code.ok_or(ErrorCode::ResultUnavailable)?;
    if status != 200 {
        return Ok(json!({"phase":"connect","status":status,"tls_verified":false}));
    }
    let tls = match tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, io)
        .await
    {
        Ok(tls) => tls,
        Err(_) => return Ok(json!({"phase":"tls","error":"tls_rejected","tls_verified":false})),
    };
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_headers(64)
        .max_buf_size(16 * 1024)
        .handshake(TokioIo::new(tls))
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    let _driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let (parts, body) = sender
        .send_request(upstream)
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?
        .into_parts();
    let headers = fields(&parts.headers)?;
    let body = Limited::new(body, 16 * 1024)
        .collect()
        .await
        .map_err(|_| ErrorCode::ResultUnavailable)?;
    let trailers = body.trailers().map(fields).transpose()?.unwrap_or_default();
    Ok(
        json!({"phase":"http","status":parts.status.as_u16(),"tls_verified":true,
        "headers":headers,"trailers":trailers,"body":body.to_bytes().to_vec()}),
    )
}

fn fields(headers: &http::HeaderMap) -> Result<Vec<(String, String)>> {
    if headers.len() > 64
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            > 16 * 1024
    {
        return Err(ErrorCode::LimitExceeded.into());
    }
    headers
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str().into(),
                value
                    .to_str()
                    .map_err(|_| ErrorCode::ResultUnavailable)?
                    .into(),
            ))
        })
        .collect()
}
struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
