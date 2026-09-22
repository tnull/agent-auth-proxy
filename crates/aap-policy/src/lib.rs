//! Pure authorization and destination rules without networking or secret access.

use std::net::IpAddr;

pub mod catalog;
mod mcp;
pub mod target;
pub mod tcp;
pub use catalog::*;
pub use target::Target;
pub use tcp::{TcpLimits, TcpProfile, validate_tcp_profiles};

#[cfg(test)]
mod mcp_tests;

/// Public unicast destinations only; special destinations need exact enrollment.
pub fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && ((b == 0 && matches!(c, 0 | 2))
                        || (b == 88 && c == 99)
                        || b == 168
                        || (b == 31 && c == 196)
                        || (b == 52 && c == 193)
                        || (b == 175 && c == 48)))
                || (a == 198 && (matches!(b, 18 | 19) || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Conservative ordinary global-unicast profile. Special-purpose
            // and transition ranges require explicit enrollment, even where
            // IANA permits routing. Never infer a route through mapped IPv4.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
                && !(s[0] == 0x2620 && s[1] == 0x004f && s[2] == 0x8000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_unicast_is_distinct_from_special_destinations() {
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(
                is_public_address(address.parse().unwrap()),
                "public unicast rejected: {address}"
            );
        }
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "64:ff9b::808:808",
        ] {
            assert!(
                !is_public_address(address.parse().unwrap()),
                "special destination admitted: {address}"
            );
        }
    }
}
