use crate::{Method, VERSION};
use aap_auth::Redactor;
use aap_types::{ErrorCode, Result};
use http::{HeaderMap, HeaderValue, StatusCode};

#[derive(Clone, Copy)]
pub(super) enum Format {
    Empty,
    Json,
    Sse,
}
pub(super) struct Admitted {
    pub format: Format,
    pub native: Option<HeaderValue>,
    pub redactor: Redactor,
}

pub(super) fn admit(
    method: Method,
    status: StatusCode,
    headers: &HeaderMap,
    previous: Option<&HeaderValue>,
    template: &Redactor,
) -> Result<Admitted> {
    if headers.len() > 64
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
            > 16 * 1024
    {
        return Err(ErrorCode::LimitExceeded.into());
    }
    for name in [
        "content-type",
        "content-encoding",
        "mcp-session-id",
        "mcp-protocol-version",
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
    }
    if headers.contains_key("set-cookie")
        || headers.contains_key("trailer")
        || headers
            .get("content-encoding")
            .is_some_and(|value| value != "identity")
        || headers
            .get("mcp-protocol-version")
            .is_some_and(|value| value != VERSION)
    {
        return Err(ErrorCode::InspectionUnavailable.into());
    }
    let empty = matches!(method, Method::Initialized | Method::Cancel);
    if status
        != if empty {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        }
    {
        return Err(if matches!(
            status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
        ) {
            ErrorCode::AuthFailed
        } else {
            ErrorCode::InspectionUnavailable
        }
        .into());
    }
    let native = if let Some(value) = headers.get("mcp-session-id") {
        if method != Method::Initialize
            || value.as_bytes().is_empty()
            || value.as_bytes().len() > 1024
            || !value
                .as_bytes()
                .iter()
                .all(|byte| (0x21..=0x7e).contains(byte))
        {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        let mut value = value.clone();
        value.set_sensitive(true);
        Some(value)
    } else {
        None
    };
    let format = if empty {
        Format::Empty
    } else {
        let media = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .ok_or(ErrorCode::InspectionUnavailable)?;
        let mut parts = media.split(';');
        let media = parts.next().unwrap_or("").trim();
        if let Some(parameter) = parts.next()
            && !parameter.trim().eq_ignore_ascii_case("charset=utf-8")
        {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        if parts.next().is_some() {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        if media.eq_ignore_ascii_case("application/json") {
            Format::Json
        } else if media.eq_ignore_ascii_case("text/event-stream") {
            Format::Sse
        } else {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
    };
    let mut redactor = template.fresh();
    if let Some(value) = native.as_ref().or(previous) {
        redactor = redactor.merged(&Redactor::new(&[value.as_bytes()])?)?;
    }
    Ok(Admitted {
        format,
        native,
        redactor,
    })
}
