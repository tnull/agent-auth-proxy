//! Credential-free authority and request contracts for inspected HTTPS ingress.

use crate::{ErrorCode, Result};
use serde::{Deserialize, Serialize};

pub struct ConnectAuthority {
    host: String,
    port: u16,
}
impl ConnectAuthority {
    pub fn parse(authority: &str) -> Result<Self> {
        let invalid = || crate::Error::new(ErrorCode::RequestInvalid);
        if authority.len() > 512 || !authority.is_ascii() {
            return Err(invalid());
        }
        let (host, port) = authority.rsplit_once(':').ok_or_else(invalid)?;
        let parsed_port: u16 = port.parse().map_err(|_| invalid())?;
        if parsed_port == 0 || parsed_port.to_string() != port {
            return Err(invalid());
        }
        let host = if host.starts_with('[') && host.ends_with(']') {
            host[1..host.len() - 1]
                .parse::<std::net::Ipv6Addr>()
                .map_err(|_| invalid())?
                .to_string()
        } else if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            if ip.to_string() != host {
                return Err(invalid());
            }
            ip.to_string()
        } else {
            if host.is_empty()
                || host.len() > 253
                || host
                    .rsplit('.')
                    .next()
                    .is_none_or(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
                || host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
            {
                return Err(invalid());
            }
            host.to_ascii_lowercase()
        };
        Ok(Self {
            host,
            port: parsed_port,
        })
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn authority(&self) -> String {
        format!("{}:{}", self.uri_host(), self.port)
    }
    pub fn origin(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.uri_host())
        } else {
            format!("https://{}", self.authority())
        }
    }
    fn uri_host(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}

/// The trusted engine, not a proxy header, chooses the unique resource profile.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardRequest {
    pub request_id: String,
    pub auth_context: Option<String>,
    pub method: String,
    pub target: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_base64: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_authorities_are_explicit_canonical_endpoints() {
        let authority =
            ConnectAuthority::parse("Example.Test:443").expect("explicit DNS authority rejected");
        assert_eq!(authority.host(), "example.test");
        assert_eq!(authority.port(), 443);
        assert_eq!(authority.authority(), "example.test:443");
        assert_eq!(authority.origin(), "https://example.test");
        let authority = ConnectAuthority::parse("127.0.0.1:8443").unwrap();
        assert_eq!(authority.origin(), "https://127.0.0.1:8443");
        let authority = ConnectAuthority::parse("[::1]:443").unwrap();
        assert_eq!(authority.host(), "::1");
        assert_eq!(authority.origin(), "https://[::1]");
        for invalid in [
            "example.test",
            "example.test:",
            "example.test:0",
            "example.test:0443",
            "example.test:65536",
            "https://example.test:443",
            "example.test:443/path",
            "example.test:443?x",
            "example.test:443#x",
            "user@example.test:443",
            "example.test.:443",
            "*.example.test:443",
            "example..test:443",
            "-example.test:443",
            "127.1:443",
            "2130706433:443",
            "[fe80::1%eth0]:443",
            "::1:443",
            "[::1]:+443",
            "é.test:443",
        ] {
            assert!(
                ConnectAuthority::parse(invalid).is_err(),
                "ambiguous authority accepted: {invalid}"
            );
        }
    }

    #[test]
    fn forward_inputs_cannot_choose_a_resource_or_session() {
        for field in ["resource", "session_id", "store", "approve"] {
            let input = format!(
                r#"{{"request_id":"x","method":"GET","target":"https://fixture.test/","{field}":"override"}}"#
            );
            assert!(crate::json::decode::<ForwardRequest>(input.as_bytes()).is_err());
        }
    }
}
