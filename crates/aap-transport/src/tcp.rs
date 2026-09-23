//! One admitted raw TCP connection. No DNS, authentication, retry, or framing.

pub mod relay;

use crate::Cancellation;
use aap_types::{BoxFuture, ErrorCode, Result};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Instant,
};

pub struct TcpEndpoint {
    authority: String,
    address: SocketAddr,
}

impl TcpEndpoint {
    /// The host must authorize every resolver result before constructing this
    /// endpoint. These structural checks do not grant destination access.
    pub fn new(authority: &str, address: SocketAddr) -> Result<Self> {
        let parsed = aap_types::proxy::ConnectAuthority::parse(authority)?;
        if parsed.authority() != authority
            || parsed.port() != address.port()
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || parsed
                .host()
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip != address.ip())
            || matches!(address, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(Self {
            authority: authority.to_owned(),
            address,
        })
    }
    pub fn authority(&self) -> &str {
        &self.authority
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

/// Trusted native I/O seam, not a socket exposed through the agent service.
pub trait TcpIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TcpIo for T {}
pub type TcpSocket = Box<dyn TcpIo>;

pub trait TcpConnector: Send + Sync {
    /// One attempt with an absolute deadline at most ten seconds away. The
    /// engine marks dispatch before calling: an accept/greeting may have effects.
    /// After success, the stream owner enforces cancellation and relay budgets.
    fn connect(
        &self,
        endpoint: TcpEndpoint,
        deadline: Instant,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<TcpSocket>>;
}

pub struct SystemTcpConnector;

impl TcpConnector for SystemTcpConnector {
    fn connect(
        &self,
        endpoint: TcpEndpoint,
        deadline: Instant,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<TcpSocket>> {
        Box::pin(async move {
            // Connect by SocketAddr, never by hostname or a list of candidates.
            // Dropping this future drops the only owned connection attempt.
            let socket = attempt(
                deadline,
                cancellation,
                tokio::net::TcpStream::connect(endpoint.address),
            )
            .await?;
            Ok(Box::new(socket) as TcpSocket)
        })
    }
}

async fn attempt<T>(
    deadline: Instant,
    cancellation: Cancellation,
    connect: impl Future<Output = std::io::Result<T>>,
) -> Result<T> {
    let now = Instant::now();
    if cancellation.is_cancelled() || deadline <= now {
        return Err(ErrorCode::UpstreamUnavailable.into());
    }
    if deadline - now > Duration::from_secs(10) {
        return Err(ErrorCode::RequestInvalid.into());
    }
    // Once the attempt may have been polled, all abnormal outcomes are uncertain.
    // Never detach a task, retry, fail over, or infer non-execution from no payload.
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ErrorCode::OutcomeUnknown.into()),
        _ = tokio::time::sleep_until(deadline) => Err(ErrorCode::OutcomeUnknown.into()),
        result = connect => result.map_err(|_| ErrorCode::OutcomeUnknown.into()),
    };
    if cancellation.is_cancelled() || Instant::now() >= deadline {
        return Err(ErrorCode::OutcomeUnknown.into());
    }
    result
}

#[cfg(test)]
mod tests;
