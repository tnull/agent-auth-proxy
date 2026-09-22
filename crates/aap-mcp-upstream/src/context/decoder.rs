use super::{
    Context, Exchange,
    headers::{Admitted, Format},
};
use crate::{MAX_REQUEST, MAX_RESPONSE, Message, Ping, Profile, Request, SseDecoder};
use aap_auth::Redactor;
use aap_types::{ErrorCode, Result};
use http::{HeaderValue, StatusCode};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub struct SafeResponse {
    pub status: StatusCode,
    pub content_type: Option<&'static str>,
    pub body: Vec<u8>,
}
/// A complete validated response, with any private state change still staged.
pub struct Completion {
    pub(super) binding: Arc<()>,
    pub(super) serial: u64,
    pub(super) native: Option<HeaderValue>,
    pub(super) success: bool,
    pub(super) response: SafeResponse,
}
impl Completion {
    pub fn response(&self) -> &SafeResponse {
        &self.response
    }
}

/// Owns bounded in-flight private data. Dropping it does not commit a session;
/// the owner must also abandon the matching Exchange on cancellation/drop.
pub struct ResponseDecoder {
    pub(super) binding: Arc<()>,
    pub(super) identity: Arc<()>,
    pub(super) serial: u64,
    pub(super) native: Option<HeaderValue>,
    pub(super) failed: bool,
    fault: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    profile: Arc<Profile>,
    request: Arc<Request>,
    format: Format,
    status: StatusCode,
    redactor: Redactor,
    framer: SseDecoder,
    body: Vec<u8>,
    final_message: Option<Vec<u8>>,
    seen_pings: BTreeSet<String>,
    bytes: usize,
}
impl ResponseDecoder {
    pub(super) fn new(
        context: &Context,
        exchange: &Exchange,
        status: StatusCode,
        admitted: Admitted,
    ) -> Self {
        Self {
            binding: context.binding.clone(),
            identity: Arc::new(()),
            serial: exchange.serial,
            native: admitted.native,
            failed: false,
            fault: context.fault.clone(),
            cancelled: exchange.cancelled.clone(),
            profile: context.profile.clone(),
            request: exchange.request.clone(),
            format: admitted.format,
            status,
            redactor: admitted.redactor,
            framer: SseDecoder::default(),
            body: Vec::new(),
            final_message: None,
            seen_pings: BTreeSet::new(),
            bytes: 0,
        }
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Ping>> {
        self.live()?;
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
            self.fault.store(true, Ordering::Release);
            self.body = Vec::new();
            self.final_message = None;
        }
        result
    }
    fn push_inner(&mut self, bytes: &[u8]) -> Result<Vec<Ping>> {
        if bytes.len() > MAX_REQUEST || bytes.len() > MAX_RESPONSE - self.bytes {
            return Err(ErrorCode::LimitExceeded.into());
        }
        self.bytes += bytes.len();
        match self.format {
            Format::Empty if !bytes.is_empty() => Err(ErrorCode::InspectionUnavailable.into()),
            Format::Empty => Ok(Vec::new()),
            Format::Json => {
                self.body.extend_from_slice(bytes);
                Ok(Vec::new())
            }
            Format::Sse => {
                let mut pings = Vec::new();
                for message in self.framer.push(bytes)? {
                    if self.final_message.is_some() {
                        return Err(ErrorCode::InspectionUnavailable.into());
                    }
                    match self.profile.response(
                        &self.request,
                        self.serial,
                        &message,
                        &self.redactor,
                    )? {
                        Message::Response(body) => self.final_message = Some(body),
                        Message::Ping(mut ping) => {
                            if !self.seen_pings.insert(ping.id.to_string()) {
                                return Err(ErrorCode::InspectionUnavailable.into());
                            }
                            ping.owner = Some(self.identity.clone());
                            pings.push(ping);
                        }
                    }
                }
                Ok(pings)
            }
        }
    }
    pub fn finish(self) -> Result<Completion> {
        self.live()?;
        let fault = self.fault.clone();
        let result = self.finish_inner();
        if result.is_err() {
            fault.store(true, Ordering::Release);
        }
        result
    }
    fn finish_inner(self) -> Result<Completion> {
        let (content_type, message) = match self.format {
            Format::Empty => (None, Vec::new()),
            Format::Json => {
                let Message::Response(body) = self.profile.response(
                    &self.request,
                    self.serial,
                    &self.body,
                    &self.redactor,
                )?
                else {
                    return Err(ErrorCode::InspectionUnavailable.into());
                };
                (Some("application/json"), body)
            }
            Format::Sse => {
                self.framer.finish()?;
                (
                    Some("text/event-stream"),
                    self.final_message.ok_or(ErrorCode::InspectionUnavailable)?,
                )
            }
        };
        let success = message.is_empty()
            || crate::wire::decode(&message, MAX_RESPONSE)?
                .get("result")
                .is_some();
        let body = if matches!(self.format, Format::Sse) {
            if message.len() > MAX_RESPONSE - 8 {
                return Err(ErrorCode::LimitExceeded.into());
            }
            let mut body = Vec::with_capacity(message.len() + 8);
            body.extend_from_slice(b"data: ");
            body.extend_from_slice(&message);
            body.extend_from_slice(b"\n\n");
            body
        } else {
            message
        };
        Ok(Completion {
            binding: self.binding,
            serial: self.serial,
            native: self.native,
            success,
            response: SafeResponse {
                status: self.status,
                content_type,
                body,
            },
        })
    }
    fn live(&self) -> Result<()> {
        if self.failed || self.fault.load(Ordering::Acquire) {
            return Err(ErrorCode::SessionInvalid.into());
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ErrorCode::RequestConflict.into());
        }
        Ok(())
    }
}
