//! Exact HTTPS authority and route admission, before any credential lookup.

use crate::catalog::{ResourceProfile, Route, routing_header, valid_alias};
use aap_types::{ErrorCode, Result};

#[derive(Clone, Debug)]
pub struct Target {
    url: url::Url,
}

impl Target {
    pub fn parse(input: &str) -> Result<Self> {
        let invalid = || aap_types::Error::new(ErrorCode::RequestInvalid);
        if input.len() > 16_384
            || !input.starts_with("https://")
            || !input.is_ascii()
            || input
                .bytes()
                .any(|b| b <= b' ' || b == 127 || b == b'\\' || b == b'#')
        {
            return Err(invalid());
        }
        let uri: http::Uri = input.parse().map_err(|_| invalid())?;
        let authority = uri.authority().ok_or_else(invalid)?;
        let url = url::Url::parse(input).map_err(|_| invalid())?;
        let host = url.host_str().ok_or_else(invalid)?;
        if authority.as_str().contains('@')
            || !url.username().is_empty()
            || url.password().is_some()
            || host.ends_with('.')
            || !authority.host().eq_ignore_ascii_case(host)
            || url.port_or_known_default() == Some(0)
        {
            return Err(invalid());
        }
        let raw_path = if uri.path().is_empty() {
            "/"
        } else {
            uri.path()
        };
        if raw_path != url.path()
            || uri.query() != url.query()
            || raw_path.contains("//")
            || raw_path.contains(';')
            || !valid_encoding(raw_path, true)
            || !valid_encoding(uri.query().unwrap_or(""), false)
        {
            return Err(invalid());
        }
        Ok(Self { url })
    }
    pub fn origin(&self) -> String {
        self.url.origin().ascii_serialization()
    }
    pub fn host(&self) -> &str {
        self.url.host_str().expect("validated HTTPS host")
    }
    pub fn port(&self) -> u16 {
        self.url
            .port_or_known_default()
            .expect("validated HTTPS port")
    }
    pub fn path(&self) -> &str {
        self.url.path()
    }
    pub fn query(&self) -> Option<&str> {
        self.url.query()
    }
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }
}

fn valid_encoding(value: &str, path: bool) -> bool {
    let bytes = value.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] == b'%' {
            if offset + 2 >= bytes.len() {
                return false;
            }
            let Some(high) = (bytes[offset + 1] as char).to_digit(16) else {
                return false;
            };
            let Some(low) = (bytes[offset + 2] as char).to_digit(16) else {
                return false;
            };
            let decoded = (high * 16 + low) as u8;
            if decoded < 32
                || decoded == 127
                || (path && matches!(decoded, b'.' | b'/' | b'\\' | b'%' | b';' | b'?' | b'#'))
            {
                return false;
            }
            offset += 3;
        } else {
            offset += 1;
        }
    }
    true
}

impl ResourceProfile {
    pub fn authorize<'a>(
        &'a self,
        method: &str,
        target: &Target,
        body_size: usize,
    ) -> Result<&'a Route> {
        if self.origin != target.origin() {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let route = self
            .routes
            .iter()
            .find(|route| {
                route.method == method
                    && route.path == target.path()
                    && route.query.as_deref() == target.query()
            })
            .ok_or_else(|| aap_types::Error::new(ErrorCode::PolicyDenied))?;
        if body_size > route.max_request_bytes {
            return Err(ErrorCode::LimitExceeded.into());
        }
        Ok(route)
    }
    pub fn validate(&self) -> Result<()> {
        use crate::catalog::{AddressPolicy, Authentication};
        let invalid = || aap_types::Error::new(ErrorCode::RequestInvalid);
        let origin = Target::parse(&self.origin)?;
        if !valid_alias(&self.id)
            || origin.origin() != self.origin
            || origin.query().is_some()
            || self.routes.is_empty()
            || self.routes.len() > 256
        {
            return Err(invalid());
        }
        if let AddressPolicy::Pinned(pins) = &self.addresses {
            let mut seen = std::collections::HashSet::new();
            if pins.is_empty()
                || pins.len() > 64
                || pins
                    .iter()
                    .any(|ip| ip.is_unspecified() || ip.is_multicast() || !seen.insert(ip))
            {
                return Err(invalid());
            }
        }
        let mut seen = std::collections::HashSet::new();
        for route in &self.routes {
            if !matches!(
                route.method.as_str(),
                "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
            ) || !route.path.starts_with('/')
                || route.path.contains('?')
                || route.max_request_bytes == 0
                || route.max_request_bytes > 128 * 1024 * 1024
                || route.max_response_bytes == 0
                || route.max_response_bytes > 128 * 1024 * 1024
                || !seen.insert((&route.method, &route.path, &route.query))
                || route.allowed_headers.len() > 64
            {
                return Err(invalid());
            }
            let target = Target::parse(&format!(
                "{}{}{}",
                self.origin,
                route.path,
                route
                    .query
                    .as_ref()
                    .map(|query| format!("?{query}"))
                    .unwrap_or_default()
            ))?;
            if target.origin() != self.origin
                || target.path() != route.path
                || target.query() != route.query.as_deref()
            {
                return Err(invalid());
            }
            let mut headers = std::collections::HashSet::new();
            for name in &route.allowed_headers {
                let parsed =
                    http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
                if parsed.as_str() != name
                    || routing_header(name)
                    || name == "authorization"
                    || !headers.insert(name)
                {
                    return Err(invalid());
                }
            }
        }
        match &self.auth {
            Authentication::None => {}
            Authentication::ApiKey {
                item_id,
                header,
                prefix,
                ..
            }
            | Authentication::Mcp {
                item_id,
                header,
                prefix,
                ..
            } => {
                let parsed =
                    http::HeaderName::from_bytes(header.as_bytes()).map_err(|_| invalid())?;
                if !valid_alias(item_id)
                    || parsed.as_str() != header
                    || routing_header(header)
                    || prefix.len() > 128
                    || !prefix.is_ascii()
                    || http::HeaderValue::from_str(prefix).is_err()
                    || self
                        .routes
                        .iter()
                        .any(|route| route.allowed_headers.contains(header))
                {
                    return Err(invalid());
                }
            }
            Authentication::Form { login } => {
                use aap_types::profile::LoginEncoding;
                let page = Target::parse(&login.page)?;
                let target = Target::parse(&login.target)?;
                let page_route = self.authorize("GET", &page, 0)?;
                let login_route = self.authorize("POST", &target, 0)?;
                if let Some(redirect) = &login.post_login_redirect {
                    let destination = Target::parse(redirect)?;
                    let route = self.authorize("GET", &destination, 0)?;
                    if login.success.status != 303
                        || destination.as_str() != redirect
                        || destination.query().is_some()
                        || redirect == &login.page
                        || redirect == &login.target
                        || route.streaming
                        || route.max_response_bytes > 256 * 1024
                    {
                        return Err(invalid());
                    }
                } else if !(200..300).contains(&login.success.status) {
                    return Err(invalid());
                }
                let is_json = login.encoding == LoginEncoding::Json;
                let selector_valid = |value: &str| {
                    !value.is_empty()
                        && value.len() <= 256
                        && !value.chars().any(char::is_control)
                        && (!is_json || valid_pointer(value))
                };
                if page_route.streaming
                    || login_route.streaming
                    || page_route.max_response_bytes > 256 * 1024
                    || login_route.max_request_bytes > 256 * 1024
                    || login_route.max_response_bytes > 256 * 1024
                    || !selector_valid(&login.fields.username)
                    || !selector_valid(&login.fields.password)
                    || selectors_overlap(&login.fields.username, &login.fields.password, is_json)
                    || !(200..400).contains(&login.success.status)
                    || login.success.cookie_names.is_empty()
                    || login.success.cookie_names.len() > 32
                    || !valid_pointer(&login.success.json_pointer)
                    || login.success.expected.is_null()
                    || login.success.expected.is_array()
                    || login.success.expected.is_object()
                    || login
                        .success
                        .expected
                        .as_str()
                        .is_some_and(|value| value.len() > 256)
                {
                    return Err(invalid());
                }
                let mut names = std::collections::HashSet::new();
                for name in &login.success.cookie_names {
                    if name.len() > 256
                        || http::HeaderName::from_bytes(name.as_bytes()).is_err()
                        || !names.insert(name)
                    {
                        return Err(invalid());
                    }
                }
                if let Some(csrf) = &login.csrf
                    && (!valid_pointer(&csrf.response_pointer)
                        || !selector_valid(&csrf.submit_field)
                        || selectors_overlap(&csrf.submit_field, &login.fields.username, is_json)
                        || selectors_overlap(&csrf.submit_field, &login.fields.password, is_json))
                {
                    return Err(invalid());
                }
            }
        }
        if let Authentication::Mcp { tools, header, .. } = &self.auth {
            self.validate_mcp(tools, header)?;
        }
        Ok(())
    }
}

fn selectors_overlap(left: &str, right: &str, json: bool) -> bool {
    left == right
        || (json
            && (left
                .strip_prefix(right)
                .is_some_and(|suffix| suffix.starts_with('/'))
                || right
                    .strip_prefix(left)
                    .is_some_and(|suffix| suffix.starts_with('/'))))
}

fn valid_pointer(pointer: &str) -> bool {
    if !pointer.starts_with('/') || pointer.len() > 4096 || pointer.chars().any(char::is_control) {
        return false;
    }
    let mut chars = pointer.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::catalog::{AddressPolicy, Authentication};

    pub fn profile() -> ResourceProfile {
        ResourceProfile {
            id: "site".into(),
            origin: "https://example.test".into(),
            addresses: AddressPolicy::Public,
            routes: vec![Route {
                method: "POST".into(),
                path: "/login".into(),
                query: None,
                max_request_bytes: 1024,
                max_response_bytes: 2048,
                allowed_headers: vec!["content-type".into()],
                streaming: false,
                require_approval: false,
            }],
            auth: Authentication::None,
        }
    }

    #[test]
    fn parsing_rejects_ambiguous_or_credential_bearing_targets() {
        assert!(
            Target::parse("https://example.test/login").is_ok(),
            "valid HTTPS target rejected"
        );
        for target in [
            "http://example.test/login",
            "https://u:p@example.test/login",
            "https://example.test/login#fragment",
            "https://example.test\\@other.test/login",
            "https://example.test/a/../login",
            "https://example.test/%2e%2e/login",
            "https://example.test/log%2fin",
            "https://example.test/login?x=%zz",
            "https://example.test./login",
            "https://example.test/login\n",
            "https://example.test:0/login",
        ] {
            assert!(
                Target::parse(target).is_err(),
                "ambiguous target accepted: {target}"
            );
        }
    }

    #[test]
    fn origin_method_query_and_size_must_all_match() {
        let profile = profile();
        assert!(
            profile
                .authorize(
                    "POST",
                    &Target::parse("https://example.test/login").unwrap(),
                    10
                )
                .is_ok(),
            "enrolled route denied"
        );
        for target in [
            "https://example.test.attacker.test/login",
            "https://example.test:444/login",
            "https://example.test/login?next=evil",
            "https://example.test/admin",
        ] {
            assert!(
                profile
                    .authorize("POST", &Target::parse(target).unwrap(), 10)
                    .is_err()
            );
        }
        let target = Target::parse("https://example.test/login").unwrap();
        assert!(profile.authorize("GET", &target, 10).is_err());
        assert!(profile.authorize("post", &target, 10).is_err());
        assert!(profile.authorize("POST", &target, 1025).is_err());
    }

    #[test]
    fn unsafe_profiles_are_rejected_at_configuration_time() {
        let mut p = profile();
        assert!(p.validate().is_ok());
        p.routes[0].max_request_bytes = 0;
        assert!(p.validate().is_err(), "unbounded/zero route limit accepted");
        p = profile();
        p.routes.push(p.routes[0].clone());
        assert!(p.validate().is_err());
        p = profile();
        p.origin.push_str("/login");
        assert!(p.validate().is_err());
    }

    #[test]
    fn invalid_header_routes_and_auth_profiles_are_rejected() {
        let baseline = profile();
        for header in [
            "authorization",
            "cookie",
            "host",
            "content-length",
            "proxy-authorization",
            "X-Custom",
            "bad\r\nname",
        ] {
            let mut p = baseline.clone();
            p.routes[0].allowed_headers = vec![header.into()];
            assert!(
                p.validate().is_err(),
                "unsafe header allowlist accepted: {header}"
            );
        }
        let mut p = baseline.clone();
        p.addresses = AddressPolicy::Pinned(vec![]);
        assert!(p.validate().is_err());
        for (method, path, query) in [
            ("post", "/login", None),
            ("CONNECT", "/login", None),
            ("POST", "/a/../login", None),
            ("POST", "/login?x=1", None),
            ("POST", "/login", Some("%zz")),
        ] {
            let mut p = baseline.clone();
            p.routes[0].method = method.into();
            p.routes[0].path = path.into();
            p.routes[0].query = query.map(String::from);
            assert!(p.validate().is_err());
        }
        let mut p = baseline;
        p.auth = Authentication::ApiKey {
            item_id: "key".into(),
            header: "host".into(),
            prefix: "".into(),
            provider: aap_types::profile::ProviderKind::Generic,
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn form_profiles_bind_fields_csrf_routes_and_success_evidence() {
        use aap_types::profile::{CsrfProfile, LoginEncoding, LoginProfile, LoginSuccess};
        let mut baseline = profile();
        baseline.routes[0].path = "/session".into();
        let mut page = baseline.routes[0].clone();
        page.method = "GET".into();
        page.path = "/login".into();
        baseline.routes.push(page);
        baseline.auth = Authentication::Form {
            login: LoginProfile {
                page: "https://example.test/login".into(),
                target: "https://example.test/session".into(),
                encoding: LoginEncoding::Form,
                fields: aap_types::CredentialFields {
                    username: "username".into(),
                    password: "password".into(),
                },
                username_visible: false,
                post_login_redirect: None,
                success: LoginSuccess {
                    status: 200,
                    cookie_names: vec!["__Host-session".into()],
                    json_pointer: "/authenticated".into(),
                    expected: serde_json::json!(true),
                },
                csrf: Some(CsrfProfile {
                    response_pointer: "/csrf".into(),
                    submit_field: "csrf".into(),
                }),
            },
        };
        assert!(baseline.validate().is_ok());
        for case in 0..9 {
            let mut p = baseline.clone();
            let Authentication::Form { login } = &mut p.auth else {
                unreachable!()
            };
            match case {
                0 => login.target = "https://other.test/session".into(),
                1 => login.fields.username = login.fields.password.clone(),
                2 => login.page = login.target.clone(),
                3 => login.success.cookie_names.clear(),
                4 => login.success.status = 401,
                5 => login.csrf.as_mut().unwrap().response_pointer = "/bad~2pointer".into(),
                6 => login.csrf.as_mut().unwrap().submit_field = login.fields.password.clone(),
                7 => login.success.json_pointer.clear(),
                _ => login.success.expected = serde_json::Value::Null,
            }
            assert!(
                p.validate().is_err(),
                "unsafe login profile accepted: case {case}"
            );
        }
        let Authentication::Form { login } = &mut baseline.auth else {
            unreachable!()
        };
        login.encoding = LoginEncoding::Json;
        assert!(
            baseline.validate().is_err(),
            "form selectors accepted as JSON pointers"
        );
        let Authentication::Form { login } = &mut baseline.auth else {
            unreachable!()
        };
        login.fields.username = "/username".into();
        login.fields.password = "/password".into();
        login.csrf.as_mut().unwrap().submit_field = "/csrf".into();
        assert!(baseline.validate().is_ok());
    }

    #[test]
    fn login_redirects_require_an_exact_enrolled_same_origin_get() {
        use aap_types::profile::{LoginEncoding, LoginProfile, LoginSuccess};
        let mut baseline = profile();
        baseline.routes[0].path = "/session".into();
        for path in ["/login", "/done"] {
            let mut route = baseline.routes[0].clone();
            route.method = "GET".into();
            route.path = path.into();
            baseline.routes.push(route);
        }
        baseline.auth = Authentication::Form {
            login: LoginProfile {
                page: "https://example.test/login".into(),
                target: "https://example.test/session".into(),
                encoding: LoginEncoding::Form,
                fields: aap_types::CredentialFields {
                    username: "user".into(),
                    password: "password".into(),
                },
                username_visible: false,
                csrf: None,
                success: LoginSuccess {
                    status: 303,
                    cookie_names: vec!["session".into()],
                    json_pointer: "/authenticated".into(),
                    expected: serde_json::json!(true),
                },
                post_login_redirect: Some("https://example.test/done".into()),
            },
        };
        baseline
            .validate()
            .expect("enrolled redirect profile denied");
        for case in 0..9 {
            let mut candidate = baseline.clone();
            let Authentication::Form { login } = &mut candidate.auth else {
                unreachable!()
            };
            match case {
                0 => login.post_login_redirect = Some("https://other.test/done".into()),
                1 => login.post_login_redirect = Some("https://example.test/undeclared".into()),
                2 => login.post_login_redirect = Some(login.page.clone()),
                3 => login.post_login_redirect = Some(login.target.clone()),
                4 => login.success.status = 307,
                5 => login.success.status = 308,
                6 => login.post_login_redirect = None,
                7 => candidate.routes[2].streaming = true,
                _ => candidate.routes[2].method = "POST".into(),
            }
            assert!(
                candidate.validate().is_err(),
                "unsafe redirect profile accepted: {case}"
            );
        }
    }
}
