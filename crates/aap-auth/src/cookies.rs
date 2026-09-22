//! Conservative host-only cookie custody for explicitly enrolled same-origin
//! flows. This is not a browser cookie implementation or a navigation policy.
use crate::Redactor;
use aap_policy::Target;
use aap_types::{ErrorCode, Result};
use http::{HeaderMap, HeaderValue};
use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};

pub struct CookieJar {
    origin: String,
    cookies: Vec<Cookie>,
    history: Vec<String>,
}
#[derive(Clone)]
struct Cookie {
    name: String,
    value: String,
    path: String,
    expires: Option<SystemTime>,
}
impl CookieJar {
    /// One jar per engine-authenticated session/account/context. Constructing a
    /// jar does not establish permission to make a request to this origin.
    pub fn new(origin: &Target) -> Self {
        Self {
            origin: origin.origin(),
            cookies: Vec::new(),
            history: Vec::new(),
        }
    }
    /// Always removes cookie-setting headers, including on failure. A rejected
    /// batch clears all jar authority; the caller must withhold its response and
    /// invalidate the authentication context rather than reuse partial state.
    pub fn capture(
        &mut self,
        target: &Target,
        headers: &mut HeaderMap,
        now: SystemTime,
    ) -> Result<Redactor> {
        let count = headers.get_all("set-cookie").iter().count();
        let unsupported = headers.contains_key("set-cookie2");
        let raw: Vec<_> = if count <= 8 {
            headers.get_all("set-cookie").iter().cloned().collect()
        } else {
            Vec::new()
        };
        headers.remove("set-cookie");
        headers.remove("set-cookie2");
        let result = if count > 8 {
            Err(ErrorCode::LimitExceeded.into())
        } else if unsupported {
            Err(ErrorCode::AuthProfileUnsupported.into())
        } else {
            self.capture_inner(target, &raw, now)
        };
        if result.is_err() {
            self.clear();
        }
        result
    }
    fn capture_inner(
        &mut self,
        target: &Target,
        raw: &[HeaderValue],
        now: SystemTime,
    ) -> Result<Redactor> {
        self.check_origin(target)?;
        let mut candidate = self.cookies.clone();
        let mut history = self.history.clone();
        let mut seen = HashSet::new();
        candidate.retain(|cookie| cookie.expires.is_none_or(|expiry| expiry > now));
        for header in raw {
            let cookie = parse(header, target.path(), now)?;
            if !seen.insert((cookie.name.clone(), cookie.path.clone())) {
                return Err(ErrorCode::AuthProfileUnsupported.into());
            }
            if !cookie.value.is_empty() && !history.contains(&cookie.value) {
                if history.len() == 16 {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                history.push(cookie.value.clone());
            }
            let previous = candidate
                .iter()
                .position(|old| old.name == cookie.name && old.path == cookie.path);
            if cookie.expires.is_some_and(|expiry| expiry <= now) {
                if let Some(position) = previous {
                    candidate.remove(position);
                }
            } else if let Some(position) = previous {
                candidate[position] = cookie;
            } else {
                if candidate.len() == 8 {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                candidate.push(cookie);
            }
        }
        let redactor = Redactor::new(
            &history
                .iter()
                .map(|value| value.as_bytes())
                .collect::<Vec<_>>(),
        )?;
        self.cookies = candidate;
        self.history = history;
        Ok(redactor)
    }
    /// Construct only on the private upstream side. The caller must reject or
    /// remove agent Cookie fields and must already authorize this exact route.
    pub fn header(&mut self, target: &Target, now: SystemTime) -> Result<Option<HeaderValue>> {
        self.check_origin(target)?;
        self.expire(now);
        let mut selected: Vec<_> = self
            .cookies
            .iter()
            .filter(|cookie| path_matches(&cookie.path, target.path()))
            .collect();
        // Stable ordering preserves original creation order for equal paths.
        selected.sort_by_key(|cookie| std::cmp::Reverse(cookie.path.len()));
        if selected.is_empty() {
            return Ok(None);
        }
        let joined = selected
            .iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>()
            .join("; ");
        if joined.len() > 32 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let mut value = HeaderValue::from_str(&joined).map_err(|_| ErrorCode::InternalError)?;
        value.set_sensitive(true);
        Ok(Some(value))
    }
    pub fn has_all(&mut self, names: &[String], now: SystemTime) -> Result<bool> {
        if names.is_empty() || names.len() > 8 {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        self.expire(now);
        Ok(names.iter().all(|name| {
            self.cookies
                .iter()
                .any(|cookie| &cookie.name == name && !cookie.value.is_empty())
        }))
    }
    /// Retains replaced/deleted cookie values for echo suppression until this
    /// context is revoked, with a finite history that fails closed on overflow.
    pub fn redactor(&self) -> Result<Redactor> {
        Redactor::new(
            &self
                .history
                .iter()
                .map(|value| value.as_bytes())
                .collect::<Vec<_>>(),
        )
    }
    pub fn clear(&mut self) {
        self.cookies.clear();
        self.history.clear();
    }
    fn check_origin(&self, target: &Target) -> Result<()> {
        if target.origin() != self.origin {
            Err(ErrorCode::PolicyDenied.into())
        } else {
            Ok(())
        }
    }
    fn expire(&mut self, now: SystemTime) {
        self.cookies
            .retain(|cookie| cookie.expires.is_none_or(|expiry| expiry > now));
    }
}
fn path_matches(cookie: &str, request: &str) -> bool {
    request == cookie
        || request
            .strip_prefix(cookie)
            .is_some_and(|suffix| cookie.ends_with('/') || suffix.starts_with('/'))
}
fn parse(header: &HeaderValue, request_path: &str, now: SystemTime) -> Result<Cookie> {
    let unsupported = || aap_types::Error::new(ErrorCode::AuthProfileUnsupported);
    if header.as_bytes().len() > 4096 {
        return Err(ErrorCode::LimitExceeded.into());
    }
    let raw = header.to_str().map_err(|_| unsupported())?;
    if !raw.is_ascii() || raw.chars().any(char::is_control) {
        return Err(unsupported());
    }
    let mut parts = raw.split(';');
    let (name, value) = parts
        .next()
        .ok_or_else(unsupported)?
        .split_once('=')
        .ok_or_else(unsupported)?;
    if name.is_empty()
        || name.len() > 256
        || http::HeaderName::from_bytes(name.as_bytes()).is_err()
        || !value.bytes().all(
            |byte| matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e),
        )
    {
        return Err(unsupported());
    }
    let mut seen = HashSet::new();
    let mut secure = false;
    let mut path = None;
    let mut expires = None;
    let mut max_age = None;
    for part in parts {
        let part = part.trim();
        let (name, value) = part
            .split_once('=')
            .map_or((part, None), |(name, value)| (name, Some(value)));
        let name = name.to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            return Err(unsupported());
        }
        match (name.as_str(), value) {
            ("secure", None) => secure = true,
            ("httponly", None) => {}
            ("path", Some(value)) if value.starts_with('/') && value.len() <= 2048 => {
                path = Some(value.to_owned())
            }
            ("samesite", Some(value))
                if value.eq_ignore_ascii_case("strict") || value.eq_ignore_ascii_case("lax") => {}
            ("expires", Some(value)) => {
                expires = Some(httpdate::parse_http_date(value).map_err(|_| unsupported())?)
            }
            ("max-age", Some(value)) => {
                if let Some(digits) = value.strip_prefix('-') {
                    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(unsupported());
                    }
                    max_age = Some(now);
                } else {
                    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(unsupported());
                    }
                    let seconds: u64 = value.parse().map_err(|_| unsupported())?;
                    max_age = Some(
                        now.checked_add(Duration::from_secs(seconds))
                            .ok_or(ErrorCode::LimitExceeded)?,
                    );
                }
            }
            // In particular, reject Domain (including public suffixes), None,
            // Partitioned and unknown extensions rather than guessing context.
            _ => return Err(unsupported()),
        }
    }
    if !secure || (name.to_ascii_lowercase().starts_with("__host-") && path.as_deref() != Some("/"))
    {
        return Err(unsupported());
    }
    let path = path.unwrap_or_else(|| match request_path.rfind('/') {
        Some(position) if position > 0 => request_path[..position].to_owned(),
        _ => "/".into(),
    });
    Ok(Cookie {
        name: name.to_owned(),
        value: value.to_owned(),
        path,
        expires: max_age.or(expires),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};
    fn target(path: &str) -> Target {
        Target::parse(&format!("https://fixture.test:8443{path}")).unwrap()
    }
    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("set-cookie", HeaderValue::from_str(value).unwrap());
        }
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers
    }
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }
    #[test]
    fn cookie_capture_is_private_path_scoped_and_isolated_by_origin_and_jar() {
        let mut jar = CookieJar::new(&target("/"));
        let mut response = headers(&[
            "pre=private-pre; Secure; HttpOnly; SameSite=Strict; Path=/login",
            "root=private-root; Secure; Path=/",
        ]);
        let mut redactor = jar
            .capture(&target("/login/start"), &mut response, now())
            .expect("valid private cookies rejected");
        assert!(!response.contains_key("set-cookie"));
        assert_eq!(response["content-type"], "application/json");
        let outgoing = jar
            .header(&target("/login/submit"), now())
            .unwrap()
            .unwrap();
        assert!(outgoing.is_sensitive());
        assert_eq!(outgoing, "pre=private-pre; root=private-root");
        assert_eq!(
            jar.header(&target("/logins"), now()).unwrap().unwrap(),
            "root=private-root"
        );
        assert_eq!(
            redactor.feed(b"private-pre private-root", true).unwrap(),
            "[redacted] [redacted]"
        );
        for uri in [
            "https://fixture.test/login",
            "https://other.test:8443/login",
            "https://sub.fixture.test:8443/login",
        ] {
            assert!(jar.header(&Target::parse(uri).unwrap(), now()).is_err());
        }
        let mut other = CookieJar::new(&target("/"));
        assert!(other.header(&target("/login"), now()).unwrap().is_none());
        jar.clear();
        assert!(jar.header(&target("/"), now()).unwrap().is_none());
    }
    #[test]
    fn refresh_deletion_and_expiry_keep_old_values_out_of_response_views() {
        let mut jar = CookieJar::new(&target("/"));
        jar.capture(
            &target("/login"),
            &mut headers(&["session=old-private; Secure; Path=/; Max-Age=5"]),
            now(),
        )
        .unwrap();
        jar.capture(&target("/login"), &mut headers(&["session=new-private; Secure; Path=/; Max-Age=10; Expires=Wed, 09 Jun 2021 10:18:14 GMT"]), now()).unwrap();
        assert_eq!(
            jar.header(&target("/"), now() + Duration::from_secs(6))
                .unwrap()
                .unwrap(),
            "session=new-private"
        );
        let mut redactor = jar
            .capture(
                &target("/logout"),
                &mut headers(&["session=; Secure; Path=/; Max-Age=0"]),
                now(),
            )
            .unwrap();
        assert!(jar.header(&target("/"), now()).unwrap().is_none());
        assert_eq!(
            redactor.feed(b"old-private new-private", true).unwrap(),
            "[redacted] [redacted]"
        );
        jar.capture(
            &target("/login"),
            &mut headers(&["session=short-lived; Secure; Path=/; Max-Age=1"]),
            now(),
        )
        .unwrap();
        assert!(jar.has_all(&["session".into()], now()).unwrap());
        assert!(
            !jar.has_all(&["session".into()], now() + Duration::from_secs(1))
                .unwrap()
        );
        jar.capture(
            &target("/login"),
            &mut headers(&[
                "session=expired-private; Secure; Path=/; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
            ]),
            now(),
        )
        .unwrap();
        assert!(jar.header(&target("/"), now()).unwrap().is_none());
    }
    #[test]
    fn unsupported_or_ambiguous_cookie_batches_strip_headers_and_clear_authority() {
        for invalid in [
            "session=value; Path=/",
            "session=value; Secure; Domain=fixture.test",
            "session=value; Secure; Domain=com",
            "session=value; Secure; SameSite=None",
            "session=value; Secure; Partitioned",
            "session=value; Secure; Unknown=x",
            "session=value; Secure; Path=/; Path=/other",
            "session=value; Secure; Secure",
            "session=value; Secure; Max-Age=abc",
            "session=value, other=value; Secure",
            "session=\"quoted\"; Secure",
            "session=value; Secure; Expires=invalid",
            "__Host-session=value; Secure",
            "__hOsT-session=value; Secure; Path=/restricted",
            "session=value; Secure; Path=relative",
            "session=value; Secure=yes",
            "session=value; Secure; SameSite=invalid",
        ] {
            let mut jar = CookieJar::new(&target("/"));
            jar.capture(
                &target("/"),
                &mut headers(&["session=old-private; Secure; Path=/"]),
                now(),
            )
            .expect("valid control rejected");
            let mut response = headers(&["tentative=private-tentative; Secure; Path=/", invalid]);
            assert!(
                jar.capture(&target("/"), &mut response, now()).is_err(),
                "unsafe cookie accepted: {invalid}"
            );
            assert!(!response.contains_key("set-cookie"));
            assert!(
                jar.header(&target("/"), now()).unwrap().is_none(),
                "partial or previous authority survived failed capture"
            );
        }
    }
    #[test]
    fn default_paths_prefixes_and_finite_cookie_history_are_enforced() {
        let mut jar = CookieJar::new(&target("/"));
        jar.capture(
            &target("/login/page"),
            &mut headers(&[
                "pre=private; Secure",
                "__Host-session=private-host; Secure; Path=/",
            ]),
            now(),
        )
        .expect("valid prefix/default path refused");
        assert_eq!(
            jar.header(&target("/login/action"), now())
                .unwrap()
                .unwrap(),
            "pre=private; __Host-session=private-host"
        );
        assert_eq!(
            jar.header(&target("/other"), now()).unwrap().unwrap(),
            "__Host-session=private-host"
        );
        let mut quota = CookieJar::new(&target("/"));
        for n in 0..16 {
            quota
                .capture(
                    &target("/"),
                    &mut headers(&[&format!("session=private-{n}; Secure; Path=/")]),
                    now(),
                )
                .unwrap();
        }
        assert!(
            quota
                .capture(
                    &target("/"),
                    &mut headers(&["session=over-budget; Secure; Path=/"]),
                    now()
                )
                .is_err()
        );
        assert!(quota.header(&target("/"), now()).unwrap().is_none());
        let mut count = CookieJar::new(&target("/"));
        for n in 0..8 {
            count
                .capture(
                    &target("/"),
                    &mut headers(&[&format!("c{n}=value{n}; Secure; Path=/")]),
                    now(),
                )
                .unwrap();
        }
        assert!(
            count
                .capture(
                    &target("/"),
                    &mut headers(&["ninth=value9; Secure; Path=/"]),
                    now()
                )
                .is_err()
        );
        let mut response = headers(&["session=value; Secure"]);
        response.insert("set-cookie2", HeaderValue::from_static("unknown=private"));
        assert!(jar.capture(&target("/"), &mut response, now()).is_err());
        assert!(!response.contains_key("set-cookie"));
        assert!(!response.contains_key("set-cookie2"));
    }
}
