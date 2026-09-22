use super::*;
use crate::target::tests::profile as http_profile;
use serde_json::json;

fn profile() -> TcpProfile {
    TcpProfile {
        id: "raw-fixture".into(),
        endpoint: "raw.test:9000".into(),
        addresses: AddressPolicy::Pinned(vec!["127.0.0.1".parse().unwrap()]),
        limits: TcpLimits::default(),
        inspection: stream::Inspection::PlaintextBytes,
        require_approval: false,
        require_observation: true,
    }
}

#[test]
fn enrollment_requires_canonical_endpoint_bounded_limits_and_no_credentials() {
    let valid = profile();
    valid.validate().unwrap();
    for endpoint in [
        "raw.test",
        "Raw.Test:9000",
        "raw.test:09000",
        "raw.test:0",
        "user@raw.test:9000",
        "raw.test:9000/",
        "raw.test.:9000",
        "*.test:9000",
        "[::1%lo]:9000",
        "127.1:9000",
        "https://raw.test:9000",
    ] {
        let mut changed = valid.clone();
        changed.endpoint = endpoint.into();
        assert!(
            changed.validate().is_err(),
            "noncanonical endpoint accepted: {endpoint}"
        );
    }
    let mut ip = valid.clone();
    ip.endpoint = "127.0.0.1:9000".into();
    ip.validate().unwrap();
    ip.addresses = AddressPolicy::Public;
    assert!(ip.validate().is_err());
    ip.endpoint = "[::1]:9000".into();
    ip.addresses = AddressPolicy::Pinned(vec!["::1".parse().unwrap()]);
    ip.validate().unwrap();
    for pins in [
        vec![],
        vec!["0.0.0.0"],
        vec!["224.0.0.1"],
        vec!["127.0.0.1", "127.0.0.1"],
        vec!["::"],
        vec!["ff02::1"],
        vec!["127.0.0.1"; 65],
    ] {
        let mut changed = valid.clone();
        changed.addresses =
            AddressPolicy::Pinned(pins.iter().map(|ip| ip.parse().unwrap()).collect());
        assert!(changed.validate().is_err());
    }
    let value = serde_json::to_value(valid).unwrap();
    for key in [
        "auth",
        "item_id",
        "store",
        "auth_context",
        "per_action_approval",
    ] {
        let mut changed = value.clone();
        changed[key] = json!("caller-override");
        assert!(
            aap_types::json::decode::<TcpProfile>(&serde_json::to_vec(&changed).unwrap()).is_err()
        );
    }
    for key in [
        "max_data_bytes",
        "send_limit",
        "receive_limit",
        "idle_timeout_ms",
        "lifetime_ms",
        "max_active_streams",
    ] {
        for bad in [0, u32::MAX as u64] {
            let mut changed = value.clone();
            changed["limits"][key] = json!(bad);
            let profile: TcpProfile =
                aap_types::json::decode(&serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(
                profile.validate().is_err(),
                "invalid limit accepted: {key}={bad}"
            );
        }
    }
}

#[test]
fn raw_enrollment_cannot_alias_an_inspected_resource_or_another_raw_profile() {
    let raw = profile();
    let http = http_profile();
    validate_tcp_profiles(std::slice::from_ref(&raw), std::slice::from_ref(&http)).unwrap();
    validate_tcp_profiles(&[], std::slice::from_ref(&http)).unwrap();
    for (origin, endpoint) in [
        ("https://example.test", "example.test:443"),
        ("https://example.test:8443", "example.test:8443"),
        ("https://[::1]:8443", "[::1]:8443"),
    ] {
        let mut http = http.clone();
        http.origin = origin.into();
        let mut raw = raw.clone();
        raw.endpoint = endpoint.into();
        raw.addresses =
            AddressPolicy::Pinned(vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()]);
        assert!(
            validate_tcp_profiles(&[raw], &[http]).is_err(),
            "inspected endpoint gained a raw route"
        );
    }
    let mut alias = raw.clone();
    alias.id = http.id.clone();
    assert!(validate_tcp_profiles(&[alias], &[http]).is_err());
    assert!(validate_tcp_profiles(&[raw.clone(), raw.clone()], &[]).is_err());
    let mut alias = raw.clone();
    alias.id = "other".into();
    assert!(
        validate_tcp_profiles(&[raw, alias], &[]).is_err(),
        "raw endpoint aliases can evade per-resource ceilings"
    );
    let many: Vec<_> = (0..257)
        .map(|i| {
            let mut p = profile();
            p.id = format!("raw-{i}");
            p.endpoint = format!("raw-{i}.test:9000");
            p
        })
        .collect();
    assert!(validate_tcp_profiles(&many, &[]).is_err());
    validate_tcp_profiles(&many[..256], &[]).unwrap();
    assert!(validate_tcp_profiles(&many[..256], &[http_profile()]).is_err());
}

#[test]
fn all_resolved_addresses_and_ports_are_checked_before_one_is_selected() {
    let raw = profile();
    let good = "127.0.0.1:9000".parse().unwrap();
    assert_eq!(raw.admit_addresses(&[good]).unwrap(), good);
    for candidates in [
        vec![],
        vec![good, "127.0.0.2:9000".parse().unwrap()],
        vec![good, "127.0.0.1:9001".parse().unwrap()],
        vec![good; 65],
        vec!["[::1]:9000".parse().unwrap()],
    ] {
        assert_eq!(
            raw.admit_addresses(&candidates).unwrap_err().code,
            ErrorCode::PolicyDenied
        );
    }
    let mut public = raw.clone();
    public.addresses = AddressPolicy::Public;
    let first = "1.1.1.1:9000".parse().unwrap();
    let second = "[2606:4700:4700::1111]:9000".parse().unwrap();
    assert_eq!(public.admit_addresses(&[first, second]).unwrap(), first);
    assert!(public.admit_addresses(&[first, good]).is_err());
    let mut literal = raw;
    literal.endpoint = "127.0.0.1:9000".into();
    literal.addresses = AddressPolicy::Pinned(vec![
        "127.0.0.1".parse().unwrap(),
        "127.0.0.2".parse().unwrap(),
    ]);
    assert!(
        literal
            .admit_addresses(&["127.0.0.2:9000".parse().unwrap()])
            .is_err(),
        "a literal endpoint was resolved to another host"
    );
    literal.endpoint = "[::1]:9000".into();
    literal.addresses = AddressPolicy::Pinned(vec!["::1".parse().unwrap()]);
    let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "::1".parse().unwrap(),
        9000,
        0,
        7,
    ));
    assert!(literal.admit_addresses(&[scoped]).is_err());
}
