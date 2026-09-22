//! Explicit credential-free TCP enrollment, distinct from inspected HTTPS.

use crate::{AddressPolicy, ResourceProfile, Target, catalog::valid_alias};
use aap_types::{ErrorCode, Result, proxy::ConnectAuthority, stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpProfile {
    pub id: String,
    /// Canonical host:port or [IPv6]:port; no URI, userinfo, or implicit port.
    pub endpoint: String,
    pub addresses: AddressPolicy,
    pub limits: TcpLimits,
    /// A trusted declaration for the controlled fixture, never traffic sniffing.
    pub inspection: stream::Inspection,
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub require_observation: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpLimits {
    pub max_data_bytes: u32,
    pub send_limit: u64,
    pub receive_limit: u64,
    pub idle_timeout_ms: u64,
    pub lifetime_ms: u64,
    /// Per resource per session, within the shared eight-upstream-operation cap.
    pub max_active_streams: u32,
}

impl Default for TcpLimits {
    fn default() -> Self {
        Self {
            max_data_bytes: stream::MAX_DATA_BYTES as u32,
            send_limit: stream::MAX_DIRECTION_BYTES,
            receive_limit: stream::MAX_DIRECTION_BYTES,
            idle_timeout_ms: stream::MAX_IDLE_MS,
            lifetime_ms: stream::MAX_LIFETIME_MS,
            max_active_streams: 8,
        }
    }
}

impl TcpProfile {
    pub fn validate(&self) -> Result<()> {
        let endpoint = ConnectAuthority::parse(&self.endpoint)?;
        let limits = self.limits;
        if !valid_alias(&self.id)
            || endpoint.authority() != self.endpoint
            || limits.max_data_bytes == 0
            || limits.max_data_bytes as usize > stream::MAX_DATA_BYTES
            || limits.send_limit == 0
            || limits.send_limit > stream::MAX_DIRECTION_BYTES
            || limits.receive_limit == 0
            || limits.receive_limit > stream::MAX_DIRECTION_BYTES
            || limits.idle_timeout_ms == 0
            || limits.idle_timeout_ms > stream::MAX_IDLE_MS
            || limits.lifetime_ms == 0
            || limits.lifetime_ms > stream::MAX_LIFETIME_MS
            || limits.max_active_streams == 0
            || limits.max_active_streams > 8
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        if let AddressPolicy::Pinned(pins) = &self.addresses {
            let mut seen = HashSet::new();
            if pins.is_empty()
                || pins.len() > 64
                || pins
                    .iter()
                    .any(|ip| ip.is_unspecified() || ip.is_multicast() || !seen.insert(ip))
            {
                return Err(ErrorCode::RequestInvalid.into());
            }
        }
        if let Ok(literal) = endpoint.host().parse::<IpAddr>()
            && !self.addresses.permits_all(&[literal])
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(())
    }

    /// Validate the entire resolver result, then select exactly one attempt.
    pub fn admit_addresses(&self, candidates: &[SocketAddr]) -> Result<SocketAddr> {
        self.validate()?;
        let endpoint = ConnectAuthority::parse(&self.endpoint)?;
        let literal = endpoint.host().parse::<IpAddr>().ok();
        if candidates.is_empty() || candidates.len() > 64 || candidates.iter().any(|address| {
            address.port() != endpoint.port()
                || literal.is_some_and(|ip| ip != address.ip())
                || matches!(address, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
        })
            || !self
                .addresses
                .permits_all(&candidates.iter().map(SocketAddr::ip).collect::<Vec<_>>())
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        // No connection retry/failover is authorized by this selection.
        Ok(candidates[0])
    }
}

pub fn validate_tcp_profiles(tcp: &[TcpProfile], http: &[ResourceProfile]) -> Result<()> {
    if tcp.len().saturating_add(http.len()) > 256 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    let mut aliases = HashSet::new();
    let mut inspected = HashSet::new();
    for profile in http {
        // Catalog validation owns complete HTTP/profile checks. This helper also
        // validates origins/aliases so callers cannot hide a cross-kind overlap.
        let origin = Target::parse(&profile.origin)?;
        if !valid_alias(&profile.id)
            || !aliases.insert(profile.id.as_str())
            || origin.origin() != profile.origin
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        inspected.insert(origin.origin());
    }
    let mut endpoints = HashSet::new();
    for profile in tcp {
        profile.validate()?;
        let endpoint = ConnectAuthority::parse(&profile.endpoint)?;
        // origin() is only a canonical host+port comparison here; raw TCP gains
        // no HTTPS capability or identity assurance from this normalization.
        if !aliases.insert(profile.id.as_str())
            || !endpoints.insert(profile.endpoint.as_str())
            || inspected.contains(&endpoint.origin())
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
