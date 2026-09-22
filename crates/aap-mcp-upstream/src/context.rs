//! Private upstream session ownership. No network or backing-store access.
use crate::{Method, Ping, Profile, Request, VERSION};
use aap_auth::Redactor;
use aap_types::{ErrorCode, Result};
use http::{HeaderMap, HeaderValue, StatusCode};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

mod decoder;
mod headers;
pub use decoder::{Completion, ResponseDecoder, SafeResponse};

/// Validate headers/status for a POSTed control response or notification.
/// The host must still consume an empty body through EOF, reject trailers,
/// and enforce current authority; this function does not admit a dispatch.
pub fn validate_control_ack(status: StatusCode, headers: &HeaderMap) -> Result<()> {
    headers::admit(Method::Cancel, status, headers, None, &Redactor::new(&[])?)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    New,
    Initializing,
    AwaitingInitialized,
    Ready,
    Invalid,
    Closed,
}

/// One host-bound upstream conversation. Expiry is monotonic; recreating a
/// conversation requires a new Context and does not reset engine deduplication.
pub struct Context {
    profile: Arc<Profile>,
    binding: Arc<()>,
    fault: Arc<AtomicBool>,
    state: State,
    expires: Instant,
    handshake: Instant,
    native: Option<HeaderValue>,
    next: u64,
    pending: BTreeMap<u64, Pending>,
}
struct Pending {
    method: Method,
    id: Option<Value>,
    operation: String,
    cancelled: Arc<AtomicBool>,
    response_started: bool,
}

/// The caller must eventually complete or abandon every admitted exchange,
/// including when an asynchronous operation is dropped before dispatch.
#[must_use]
pub struct Exchange {
    binding: Arc<()>,
    serial: u64,
    request: Arc<Request>,
    mapped: Option<u64>,
    cancellation_target: Option<String>,
    cancelled: Arc<AtomicBool>,
}
/// Private outbound protocol bytes and headers, never an agent-safe response.
pub struct Outgoing {
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// One owned target and private cancellation notification. Creating this stops
/// local response commitment; the engine must not send it for undispatched work.
pub struct CancellationRequest {
    pub operation: String,
    pub outgoing: Outgoing,
}

impl Context {
    /// Apply local cancellation without reserving remote control capacity.
    /// Unknown/completed/initialization IDs require no external work.
    pub fn cancel_request(
        &mut self,
        request: Request,
        now: Instant,
    ) -> Result<Option<CancellationRequest>> {
        if request.method() != Method::Cancel
            || !Arc::ptr_eq(&request.binding, &self.profile.binding)
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        self.expire(now);
        let serial = self
            .pending
            .iter()
            .find(|(_, pending)| {
                pending.id.is_some()
                    && pending.id.as_ref() == request.cancellation_id()
                    && pending.method != Method::Initialize
            })
            .map(|(serial, _)| *serial);
        match serial {
            Some(serial) => self.cancel_serial(serial),
            None => Ok(None),
        }
    }

    /// Local operation cancellation also aborts a handshake without sending
    /// a prohibited MCP initialization cancellation notification.
    pub fn cancel_operation(
        &mut self,
        operation: &str,
        now: Instant,
    ) -> Result<Option<CancellationRequest>> {
        self.expire(now);
        let Some((serial, pending)) = self
            .pending
            .iter()
            .find(|(_, pending)| pending.operation == operation)
        else {
            return Ok(None);
        };
        if matches!(pending.method, Method::Initialize | Method::Initialized) {
            self.invalidate();
            return Ok(None);
        }
        self.cancel_serial(*serial)
    }

    fn cancel_serial(&mut self, serial: u64) -> Result<Option<CancellationRequest>> {
        let pending = self
            .pending
            .get(&serial)
            .ok_or(ErrorCode::RequestConflict)?;
        if pending.id.is_none() || pending.cancelled.swap(true, Ordering::AcqRel) {
            return Ok(None);
        }
        Ok(Some(CancellationRequest {
            operation: pending.operation.clone(),
            outgoing: Outgoing {
                headers: outgoing_headers(self.native.as_ref(), true),
                body: serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0",
                    "method":"notifications/cancelled","params":{"requestId":serial}}))
                .map_err(|_| ErrorCode::InternalError)?,
            },
        }))
    }

    pub fn new(profile: Arc<Profile>, now: Instant, expires: Instant) -> Result<Self> {
        if expires <= now {
            return Err(ErrorCode::SessionInvalid.into());
        }
        Ok(Self {
            profile,
            binding: Arc::new(()),
            fault: Arc::new(AtomicBool::new(false)),
            state: State::New,
            expires: expires.min(now + Duration::from_secs(600)),
            handshake: expires.min(now + Duration::from_secs(30)),
            native: None,
            next: 1,
            pending: BTreeMap::new(),
        })
    }

    pub fn state(&mut self, now: Instant) -> State {
        self.expire(now);
        self.state
    }

    /// None acknowledges an unknown/completed/initialization cancellation
    /// locally. It is not a request to send anything upstream.
    pub fn begin(
        &mut self,
        request: Request,
        operation: &str,
        now: Instant,
    ) -> Result<Option<Exchange>> {
        self.expire(now);
        if !Arc::ptr_eq(&request.binding, &self.profile.binding)
            || !aap_types::ids::valid_id(operation, 16)
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        if matches!(self.state, State::Invalid | State::Closed) {
            return Err(ErrorCode::SessionInvalid.into());
        }
        let method = request.method();
        let admitted = match method {
            Method::Initialize => self.state == State::New,
            Method::Initialized => {
                self.state == State::AwaitingInitialized
                    && !self
                        .pending
                        .values()
                        .any(|pending| pending.method == Method::Initialized)
            }
            Method::Ping => self.state != State::New,
            Method::Cancel => self.state != State::New,
            Method::List | Method::Call => self.state == State::Ready,
        };
        if !admitted {
            return Err(ErrorCode::RequestConflict.into());
        }
        if self.pending.values().any(|pending| {
            pending.operation == operation
                || (request.id().is_some() && pending.id.as_ref() == request.id())
        }) {
            return Err(ErrorCode::RequestConflict.into());
        }
        let target = if method == Method::Cancel {
            let Some((serial, pending)) = self.pending.iter().find(|(_, pending)| {
                pending.id.as_ref() == request.cancellation_id()
                    && pending.id.is_some()
                    && pending.method != Method::Initialize
                    && !pending.cancelled.load(Ordering::Acquire)
            }) else {
                return Ok(None);
            };
            Some((
                *serial,
                pending.operation.clone(),
                pending.cancelled.clone(),
            ))
        } else {
            None
        };
        let control = is_control(method);
        if self.next > 4096
            || self
                .pending
                .values()
                .filter(|pending| is_control(pending.method) == control)
                .count()
                >= if control { 2 } else { 8 }
        {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let serial = self.next;
        self.next += 1;
        let cancelled = Arc::new(AtomicBool::new(false));
        let mapped = if let Some((target, _, cancelled)) = &target {
            cancelled.store(true, Ordering::Release);
            Some(*target)
        } else {
            request.id().map(|_| serial)
        };
        let cancellation_target = target.map(|(_, operation, _)| operation);
        if method == Method::Initialize {
            self.state = State::Initializing;
        }
        self.pending.insert(
            serial,
            Pending {
                method,
                id: request.id().cloned(),
                operation: operation.into(),
                cancelled: cancelled.clone(),
                response_started: false,
            },
        );
        Ok(Some(Exchange {
            binding: self.binding.clone(),
            serial,
            request: Arc::new(request),
            mapped,
            cancellation_target,
            cancelled,
        }))
    }

    /// Preparation is not evidence of dispatch. The engine must still perform
    /// approval, credential/version, destination, cancellation and recording checks.
    pub fn outgoing(&mut self, exchange: &Exchange, now: Instant) -> Result<Outgoing> {
        self.check(exchange, now)?;
        Ok(Outgoing {
            headers: outgoing_headers(
                if exchange.request.method() == Method::Initialize {
                    None
                } else {
                    self.native.as_ref()
                },
                exchange.request.method() != Method::Initialize,
            ),
            body: exchange.request.encode(exchange.mapped)?,
        })
    }

    /// Recheck an owned exchange without preparing or authorizing a dispatch.
    pub fn validate(&mut self, exchange: &Exchange, now: Instant) -> Result<()> {
        self.check(exchange, now)
    }

    pub fn start_response(
        &mut self,
        exchange: &Exchange,
        status: StatusCode,
        headers: &HeaderMap,
        redactor: &Redactor,
        now: Instant,
    ) -> Result<ResponseDecoder> {
        self.check(exchange, now)?;
        if self.pending[&exchange.serial].response_started {
            return Err(ErrorCode::RequestConflict.into());
        }
        let response = headers::admit(
            exchange.request.method(),
            status,
            headers,
            self.native.as_ref(),
            redactor,
        );
        let admitted = match response {
            Ok(value) => value,
            Err(error) => {
                self.invalidate();
                return Err(error);
            }
        };
        self.pending
            .get_mut(&exchange.serial)
            .expect("checked exchange")
            .response_started = true;
        Ok(ResponseDecoder::new(self, exchange, status, admitted))
    }

    /// Commit only after the host rechecks authority, custody and required
    /// observation. The opaque completion proves bounded protocol EOF, not
    /// those external prerequisites or successful business execution.
    pub fn complete(
        &mut self,
        exchange: Exchange,
        completion: Completion,
        now: Instant,
    ) -> Result<SafeResponse> {
        if !Arc::ptr_eq(&self.binding, &exchange.binding)
            || !Arc::ptr_eq(&self.binding, &completion.binding)
            || exchange.serial != completion.serial
        {
            return Err(ErrorCode::RequestConflict.into());
        }
        if let Err(error) = self.check(&exchange, now) {
            self.pending.remove(&exchange.serial);
            return Err(error);
        }
        if !self.pending[&exchange.serial].response_started {
            return Err(ErrorCode::RequestConflict.into());
        }
        self.pending.remove(&exchange.serial);
        match exchange.request.method() {
            Method::Initialize if completion.success => {
                self.native = completion.native;
                self.state = State::AwaitingInitialized;
            }
            Method::Initialize => self.invalidate(),
            Method::Initialized => self.state = State::Ready,
            _ => {}
        }
        Ok(completion.response)
    }

    /// A dropped normal operation retires its mapping without claiming remote
    /// cancellation. Dropping a handshake prevents a half-open session from use.
    pub fn abandon(&mut self, exchange: Exchange) {
        if !Arc::ptr_eq(&self.binding, &exchange.binding) {
            return;
        }
        if let Some(pending) = self.pending.remove(&exchange.serial) {
            pending.cancelled.store(true, Ordering::Release);
            if matches!(pending.method, Method::Initialize | Method::Initialized) {
                self.invalidate();
            }
        }
    }

    pub fn invalidate(&mut self) {
        if self.state != State::Closed {
            self.state = State::Invalid;
        }
        self.fault.store(true, Ordering::Release);
        self.native = None;
        self.pending.clear();
    }

    /// Invalidate locally first, returning private cleanup headers once. These
    /// do not authorize DELETE after credential, grant or observation revocation.
    pub fn close(&mut self, now: Instant) -> HeaderMap {
        self.expire(now);
        let headers = self
            .native
            .as_ref()
            .map(|native| outgoing_headers(Some(native), true))
            .unwrap_or_default();
        self.invalidate();
        self.state = State::Closed;
        headers
    }

    /// One-shot private control response owned by this live parent/decoder.
    /// The engine must separately reserve shared control capacity and authorize
    /// the child dispatch; this method performs no I/O or credential access.
    pub fn ping_reply(
        &mut self,
        exchange: &Exchange,
        decoder: &ResponseDecoder,
        ping: &Ping,
        now: Instant,
    ) -> Result<Outgoing> {
        self.check(exchange, now)?;
        if !Arc::ptr_eq(&self.binding, &decoder.binding)
            || decoder.serial != exchange.serial
            || decoder.failed
            || ping
                .owner
                .as_ref()
                .is_none_or(|owner| !Arc::ptr_eq(owner, &decoder.identity))
            || ping
                .used
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(ErrorCode::RequestConflict.into());
        }
        Ok(Outgoing {
            headers: outgoing_headers(decoder.native.as_ref().or(self.native.as_ref()), true),
            body: ping.response()?,
        })
    }

    fn expire(&mut self, now: Instant) {
        if !matches!(self.state, State::Invalid | State::Closed)
            && (self.fault.load(Ordering::Acquire)
                || now >= self.expires
                || (self.state != State::Ready && now >= self.handshake))
        {
            self.invalidate();
        }
    }
    fn check(&mut self, exchange: &Exchange, now: Instant) -> Result<()> {
        if !Arc::ptr_eq(&self.binding, &exchange.binding) {
            return Err(ErrorCode::RequestConflict.into());
        }
        self.expire(now);
        if matches!(self.state, State::Invalid | State::Closed) {
            return Err(ErrorCode::SessionInvalid.into());
        }
        if !self.pending.contains_key(&exchange.serial)
            || exchange.cancelled.load(Ordering::Acquire)
        {
            return Err(ErrorCode::RequestConflict.into());
        }
        Ok(())
    }
}
impl Exchange {
    pub fn cancellation_target(&self) -> Option<&str> {
        self.cancellation_target.as_deref()
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        self.invalidate();
    }
}
fn is_control(method: Method) -> bool {
    matches!(method, Method::Ping | Method::Initialized | Method::Cancel)
}
fn outgoing_headers(native: Option<&HeaderValue>, version: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert(
        "accept",
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    if version {
        headers.insert("mcp-protocol-version", HeaderValue::from_static(VERSION));
    }
    if let Some(native) = native {
        headers.insert("mcp-session-id", native.clone());
    }
    headers
}

#[cfg(test)]
mod tests;
