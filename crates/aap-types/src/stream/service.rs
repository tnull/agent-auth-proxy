//! Owned, runtime-neutral stream service contracts. No socket or store access.

use super::{Cause, Opened, Terminal};
use crate::{BoxFuture, OperationStatus, Result};
use std::{
    sync::Arc,
    task::{Context, Poll},
};

/// Admission is separate from connection work, allowing a local adapter to
/// finish its upgrade before starting approval, DNS, or an upstream attempt.
pub enum Admission {
    Existing(OperationStatus),
    New(Box<dyn PendingStream>),
}

/// Owns the sole attachment. Dropping it or its connection future cancels work;
/// neither can be cloned, resumed, or replayed by an operation-ID lookup.
pub trait PendingStream: Send {
    /// Stop this attachment independently of a blocked connection future.
    fn abort_handle(&self) -> Arc<dyn StreamAbort>;
    /// A returned error means the adapter could not obtain a complete result.
    /// It must not invent an engine terminal outcome or reconnect automatically.
    fn connect(self: Box<Self>) -> BoxFuture<'static, Result<Connection>>;
}

pub enum Connection {
    Opened(Box<dyn ConnectedStream>),
    Terminal(Terminal),
}

/// Session-authorized connection ownership, never a raw upstream socket.
pub trait ConnectedStream: Send {
    fn abort_handle(&self) -> Arc<dyn StreamAbort>;
    /// Current safe opening metadata, with the original remaining lifetime.
    fn opened(&self) -> Result<Opened>;

    /// Transfer the application attachment immediately, even before polling the
    /// returned future. A wire adapter must finish OPENED before calling this.
    /// End-of-direction is distinct from the final terminal result. A missing
    /// result is an error, never implicit completion from EOF. Dropping the
    /// future closes the attachment and cancels any nonterminal work.
    fn relay(
        self: Box<Self>,
        attachment: Box<dyn ApplicationIo>,
    ) -> BoxFuture<'static, Result<Terminal>>;
}

/// A stop-only capability for the already admitted operation. It grants no
/// new attachment, destination, credentials, approval, or success authority.
/// Call outside ApplicationIo callbacks; engine callbacks may hold an operation
/// lock. A remote implementation may only close its local attachment, in which
/// case missing terminal delivery still remains an error, not an invented result.
pub trait StreamAbort: Send + Sync {
    fn abort(&self, reason: AttachmentError);
    /// Wake an adapter blocked on control delivery when this operation ends.
    /// This signal is not a terminal result or evidence of successful delivery.
    fn terminated(&self) -> BoxFuture<'_, ()>;
}

/// Trusted, bounded application I/O supplied by a session adapter or embedder.
/// Calls are nonblocking and must register a wakeup before returning Pending.
/// No hidden payload queue is permitted: writes report only actual accepted
/// prefixes; framing and any retained copies count toward the relay's budget.
/// Do not reenter the same broker from these callbacks.
pub trait ApplicationIo: Send + Unpin {
    /// Read application bytes, returning 0 only for an explicit directional end.
    /// Raw framed-attachment EOF must instead return AttachmentLost. A successful
    /// count must not exceed the supplied buffer, whose contents are initialized.
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>>;

    /// Report only the accepted application prefix, excluding framing bytes.
    /// Zero for a nonempty input is failure; Pending must not accept payload.
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>>;

    /// End delivery in this direction without closing the attachment's control
    /// channel or its opposite direction. No application bytes may remain queued.
    fn poll_send_end(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), AttachmentError>>;
}

/// Fixed adapter failures. The local adapter cannot claim orderly completion,
/// approval, or upstream effects through an error result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentError {
    InvalidFrame,
    LimitExceeded,
    AttachmentLost,
    InternalError,
}
impl AttachmentError {
    pub fn cause(self) -> Cause {
        match self {
            Self::InvalidFrame => Cause::InvalidFrame,
            Self::LimitExceeded => Cause::LimitExceeded,
            Self::AttachmentLost => Cause::AttachmentLost,
            Self::InternalError => Cause::InternalError,
        }
    }
}
impl std::fmt::Display for AttachmentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrame => "invalid_frame",
            Self::LimitExceeded => "limit_exceeded",
            Self::AttachmentLost => "attachment_lost",
            Self::InternalError => "internal_error",
        })
    }
}
impl std::error::Error for AttachmentError {}
