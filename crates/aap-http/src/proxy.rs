//! Inspected HTTPS ingress. The trusted host supplies lease-bound TLS identities.
use super::*;
use aap_types::proxy::{ConnectAuthority, ForwardRequest};
use base64::{Engine, engine::general_purpose::STANDARD};

/// Called only after the session admits the destination; never exposed as an
/// agent signing API. Implementations bound issuance and keep CA keys private.
pub trait InterceptionProvider: Send + Sync {
    fn issue(
        &self,
        authority: ConnectAuthority,
    ) -> BoxFuture<'_, Result<Arc<dyn InterceptionIdentity>>>;
}
/// A short-lived leaf whose backing store lease remains revocable.
pub trait InterceptionIdentity: Send + Sync {
    fn configuration(&self) -> Arc<rustls::ServerConfig>;
    fn revalidate(&self) -> BoxFuture<'_, Result<()>>;
}

pub(super) struct Tunnel {
    upgrade: hyper::upgrade::OnUpgrade,
    authority: ConnectAuthority,
    identity: Arc<dyn InterceptionIdentity>,
    session: Arc<dyn AgentService>,
}
pub(super) async fn admit(
    mut request: http::Request<Incoming>,
    session: Arc<dyn AgentService>,
    identities: Arc<dyn InterceptionProvider>,
    pending: Arc<std::sync::Mutex<Option<Tunnel>>>,
) -> Result<Response> {
    let authority = connect_authority(&request)?;
    session.admit_connect(authority.authority()).await?;
    let identity = tokio::time::timeout(
        Duration::from_secs(10),
        identities.issue(ConnectAuthority::parse(&authority.authority())?),
    )
    .await
    .map_err(|_| ErrorCode::InspectionUnavailable)??;
    identity.revalidate().await?;
    // Admission can expire while the store or signer was busy.
    session.admit_connect(authority.authority()).await?;
    let mut pending = pending.lock().map_err(|_| ErrorCode::InternalError)?;
    if pending.is_some() {
        return Err(ErrorCode::RequestConflict.into());
    }
    *pending = Some(Tunnel {
        upgrade: hyper::upgrade::on(&mut request),
        authority,
        identity,
        session,
    });
    Ok(http::Response::new(
        Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed_unsync(),
    ))
}

pub(super) async fn serve_tunnel(tunnel: Tunnel) -> Result<()> {
    let io = tokio::time::timeout(Duration::from_secs(10), tunnel.upgrade)
        .await
        .map_err(|_| ErrorCode::InspectionUnavailable)?
        .map_err(|_| ErrorCode::InspectionUnavailable)?;
    tunnel.identity.revalidate().await?;
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsAcceptor::from(tunnel.identity.configuration()).accept(TokioIo::new(io)),
    )
    .await
    .map_err(|_| ErrorCode::InspectionUnavailable)?
    .map_err(|_| ErrorCode::InspectionUnavailable)?;
    let authority = Arc::new(tunnel.authority);
    let service = service_fn(move |request| {
        let authority = authority.clone();
        let session = tunnel.session.clone();
        let identity = tunnel.identity.clone();
        async move {
            let response = async {
                // Reject authority/headers before polling a potentially large body.
                let (parts, body) = request.into_parts();
                let mut forward =
                    forward_request(http::Request::from_parts(parts, Bytes::new()), &authority)?;
                let body = tokio::time::timeout(
                    Duration::from_secs(10),
                    Limited::new(body, 1024 * 1024).collect(),
                )
                .await
                .map_err(|_| ErrorCode::RequestInvalid)?
                .map_err(|_| ErrorCode::LimitExceeded)?;
                if body.trailers().is_some() {
                    return Err(ErrorCode::RequestInvalid.into());
                }
                forward.body_base64 = STANDARD.encode(body.to_bytes());
                identity.revalidate().await?;
                session.forward(forward).await
            }
            .await
            .unwrap_or_else(error_response);
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    http1_builder()
        .serve_connection(TokioIo::new(tls), service)
        .await
        .map_err(|_| ErrorCode::InspectionUnavailable.into())
}

fn header_bounds<B>(request: &http::Request<B>) -> Result<()> {
    let headers = request.headers();
    if request.version() != http::Version::HTTP_11
        || headers.len() > 64
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
            > 64 * 1024
        || headers
            .keys()
            .any(|name| headers.get_all(name).iter().count() != 1)
        || headers.get_all("host").iter().count() != 1
        || ["connection", "proxy-connection"].iter().any(|name| {
            headers
                .get(*name)
                .is_some_and(|value| value != "close" && value != "keep-alive")
        })
        || (headers.contains_key("content-length") && headers.contains_key("transfer-encoding"))
        || headers
            .get("transfer-encoding")
            .is_some_and(|value| value != "chunked")
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    Ok(())
}
fn connect_authority<B>(request: &http::Request<B>) -> Result<ConnectAuthority> {
    header_bounds(request)?;
    if request.method() != http::Method::CONNECT
        || request.uri().scheme().is_some()
        || request.uri().path_and_query().is_some()
        || request.headers().keys().any(|name| {
            !matches!(
                name.as_str(),
                "host" | "user-agent" | "connection" | "proxy-connection" | "content-length"
            )
        })
        || request
            .headers()
            .get("content-length")
            .is_some_and(|value| value != "0")
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let authority = ConnectAuthority::parse(
        request
            .uri()
            .authority()
            .ok_or(ErrorCode::RequestInvalid)?
            .as_str(),
    )?;
    let host = ConnectAuthority::parse(
        request.headers()["host"]
            .to_str()
            .map_err(|_| ErrorCode::RequestInvalid)?,
    )?;
    if authority.authority() != host.authority() {
        return Err(ErrorCode::PolicyDenied.into());
    }
    Ok(authority)
}
fn forward_request(
    request: http::Request<Bytes>,
    authority: &ConnectAuthority,
) -> Result<ForwardRequest> {
    header_bounds(&request)?;
    let uri = request.uri();
    if request.method() == http::Method::CONNECT
        || uri.scheme().is_some()
        || uri.authority().is_some()
        || !uri.path().starts_with('/')
        || uri.path().starts_with("//")
        || request.headers().keys().any(|name| {
            matches!(
                name.as_str(),
                "authorization" | "cookie" | "upgrade" | "expect" | "trailer" | "te"
            ) || name.as_str().starts_with("x-aap-")
                || (name.as_str().starts_with("proxy-")
                    && !matches!(name.as_str(), "proxy-auth-context" | "proxy-connection"))
        })
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let host = request.headers()["host"]
        .to_str()
        .map_err(|_| ErrorCode::RequestInvalid)?;
    let host = if host.ends_with(']') || !host.contains(':') {
        format!("{host}:443")
    } else {
        host.to_owned()
    };
    if ConnectAuthority::parse(&host)?.authority() != authority.authority() {
        return Err(ErrorCode::PolicyDenied.into());
    }
    let auth_context = request
        .headers()
        .get("proxy-auth-context")
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| Error::new(ErrorCode::RequestInvalid))
        })
        .transpose()?;
    if auth_context
        .as_ref()
        .is_some_and(|context| !aap_types::ids::valid_id(context, 32))
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    let mut headers = Vec::new();
    for (name, value) in request.headers() {
        if matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "proxy-connection"
                | "proxy-auth-context"
        ) {
            continue;
        }
        headers.push((
            name.as_str().to_owned(),
            value
                .to_str()
                .map_err(|_| ErrorCode::RequestInvalid)?
                .to_owned(),
        ));
    }
    if request.body().len() > 1024 * 1024 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    Ok(ForwardRequest {
        request_id: aap_types::ids::random_id(16).map_err(|_| ErrorCode::InternalError)?,
        auth_context,
        method: request.method().to_string(),
        target: format!(
            "{}{}",
            authority.origin(),
            uri.path_and_query()
                .ok_or(ErrorCode::RequestInvalid)?
                .as_str()
        ),
        headers,
        body_base64: STANDARD.encode(request.body()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn connect(target: &str, host: &str) -> http::Request<Bytes> {
        http::Request::builder()
            .method("CONNECT")
            .uri(target)
            .header("host", host)
            .body(Bytes::new())
            .unwrap()
    }
    #[test]
    fn connect_requires_exact_explicit_authority_and_no_payload() {
        assert_eq!(
            connect_authority(&connect("fixture.test:443", "fixture.test:443"))
                .expect("valid CONNECT denied")
                .origin(),
            "https://fixture.test"
        );
        for (target, host) in [
            ("fixture.test:443", "other.test:443"),
            ("fixture.test:443", "fixture.test"),
            ("fixture.test:443", "fixture.test:8443"),
            ("https://fixture.test:443/", "fixture.test:443"),
        ] {
            assert!(connect_authority(&connect(target, host)).is_err());
        }
        for (name, value) in [
            ("content-length", "1"),
            ("transfer-encoding", "chunked"),
            ("authorization", "secret"),
            ("proxy-authorization", "secret"),
            ("connection", "upgrade"),
            ("x-aap-session", "other"),
        ] {
            let mut request = connect("fixture.test:443", "fixture.test:443");
            request.headers_mut().insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
            assert!(connect_authority(&request).is_err(), "accepted {name}");
        }
        let mut request = connect("fixture.test:443", "fixture.test:443");
        request
            .headers_mut()
            .append("host", http::HeaderValue::from_static("fixture.test:443"));
        assert!(connect_authority(&request).is_err());
    }
    fn inner(target: &str, host: &str) -> http::Request<Bytes> {
        http::Request::builder()
            .method("POST")
            .uri(target)
            .header("host", host)
            .header("content-type", "application/json")
            .body(Bytes::from_static(b"{}"))
            .unwrap()
    }
    #[test]
    fn tunnel_request_cannot_change_authority_or_forward_local_context() {
        let authority = ConnectAuthority::parse("fixture.test:443").unwrap();
        let context = aap_types::ids::random_id(32).unwrap();
        let mut request = inner("/session?x=1", "fixture.test");
        request
            .headers_mut()
            .insert("proxy-auth-context", context.parse().unwrap());
        let forward = forward_request(request, &authority).expect("valid tunneled request denied");
        assert_eq!(forward.target, "https://fixture.test/session?x=1");
        assert_eq!(forward.auth_context.as_deref(), Some(context.as_str()));
        assert_eq!(
            forward.headers,
            vec![("content-type".into(), "application/json".into())]
        );
        assert_eq!(forward.body_base64, "e30=");
        assert!(aap_types::ids::valid_id(&forward.request_id, 16));
        for (target, host) in [
            ("/", "other.test"),
            ("/", "fixture.test:8443"),
            ("https://fixture.test/", "fixture.test"),
            ("//other.test/", "fixture.test"),
            ("*", "fixture.test"),
        ] {
            assert!(forward_request(inner(target, host), &authority).is_err());
        }
        for (name, value) in [
            ("connection", "authorization"),
            ("upgrade", "websocket"),
            ("authorization", "secret"),
            ("cookie", "secret"),
            ("proxy-authorization", "secret"),
            ("proxy-auth-context", "invalid"),
            ("x-aap-session", "other"),
            ("expect", "100-continue"),
        ] {
            let mut request = inner("/", "fixture.test");
            request.headers_mut().insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
            assert!(
                forward_request(request, &authority).is_err(),
                "accepted {name}"
            );
        }
        let mut request = inner("/", "fixture.test");
        request
            .headers_mut()
            .append("host", "fixture.test".parse().unwrap());
        assert!(forward_request(request, &authority).is_err());
        let mut request = inner("/", "fixture.test");
        request
            .headers_mut()
            .append("proxy-auth-context", context.parse().unwrap());
        request
            .headers_mut()
            .append("proxy-auth-context", context.parse().unwrap());
        assert!(forward_request(request, &authority).is_err());
    }
}
