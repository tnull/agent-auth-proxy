//! Trusted TCP operation ownership. Agent wire binding remains in the adapters.

use super::*;
use aap_observe::{
    Data, Decision, Direction, Emission, Flow, FlowContext, Inspection, Protocol, Redaction, View,
};
use aap_policy::{TcpLimits, TcpProfile};
use aap_transport::tcp::{TcpEndpoint, TcpSocket};
use aap_types::stream;

mod connect;
mod observation;
mod relay;
mod service;
mod state;
pub use relay::TcpRelay;
pub(super) use state::Operation;
use state::{AttachmentSlots, Capacity, State};

pub struct ConnectionApproval {
    pub daemon_epoch: String,
    pub session_id: String,
    pub approval_id: String,
    pub configuration_revision: u64,
    pub operation: Arc<stream::Open>,
    pub endpoint: String,
    pub limits: TcpLimits,
    pub inspection: stream::Inspection,
    pub require_observation: bool,
    pub expires_at: std::time::Instant,
}

pub enum TcpAdmission {
    Existing(OperationStatus),
    New(PendingTcp),
}

/// Owns the sole not-yet-connected attachment; dropping it cancels its operation.
pub struct PendingTcp {
    session: Session,
    operation: Arc<Operation>,
    transferred: bool,
}

/// Owned trusted connection, not a raw socket available to the agent.
pub struct ConnectedTcp {
    session: Session,
    operation: Arc<Operation>,
    details: stream::Opened,
    timing: ConnectionTiming,
    watchdog: tokio::task::JoinHandle<()>,
}

struct ConnectionTiming {
    lifetime: Instant,
    idle: Instant,
}

impl Session {
    /// Register one owned attachment without approval, DNS, credentials, or dialing.
    /// The host starts connect only after its local attachment has been established.
    pub fn admit_tcp(&self, request: stream::Open) -> Result<TcpAdmission> {
        self.check()?;
        request.validate()?;
        let mut operations = self
            .core
            .operations
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        if operations.items.contains_key(&request.request_id)
            || operations.issuances.contains_key(&request.request_id)
        {
            return Err(ErrorCode::RequestConflict.into());
        }
        if let Some(operation) = operations.streams.get(&request.request_id) {
            if *operation.request != request {
                return Err(ErrorCode::RequestConflict.into());
            }
            return Ok(TcpAdmission::Existing(operation.status()?));
        }
        let profile = self
            .core
            .host
            .configuration
            .tcp_profiles
            .iter()
            .find(|profile| {
                profile.id == request.resource && self.core.options.resources.contains(&profile.id)
            })
            .ok_or(ErrorCode::PolicyDenied)?
            .clone();
        // This reservation includes retained request/profile/status metadata.
        let bytes = 4096 + request.request_id.len() + profile.id.len() + profile.endpoint.len();
        if operations.len() >= 4096 || operations.bytes + bytes > 8 * 1024 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let attachments = AttachmentSlots {
            _session: self
                .core
                .tcp_pending
                .clone()
                .try_acquire_owned()
                .map_err(|_| ErrorCode::LimitExceeded)?,
            _host: self
                .core
                .host
                .tcp_pending
                .clone()
                .try_acquire_owned()
                .map_err(|_| ErrorCode::LimitExceeded)?,
        };
        let required = self.core.options.require_observation || profile.require_observation;
        let flow = Flow::new(
            self.core.host.configuration.recorder.clone(),
            FlowContext {
                session_id: self.id().into(),
                request_id: Some(request.request_id.clone()),
                parent_request_id: None,
                policy_version: self.core.host.configuration.catalog.configuration_revision,
                protocol: Protocol::Tcp,
            },
            required,
        )?;
        self.check()?;
        self.core
            .host
            .operation_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= 64 * 1024 * 1024)
            })
            .map_err(|_| ErrorCode::LimitExceeded)?;
        let operation = Arc::new(Operation {
            state: Mutex::new(State {
                status: OperationStatus {
                    request_id: request.request_id.clone(),
                    state: OperationState::Validated,
                    status: None,
                },
                cause: None,
                flow_started: false,
                socket: None,
                capacity: None,
                attachments: Some(attachments),
                relay: None,
                deadline: None,
                sent_bytes: 0,
                received_bytes: 0,
            }),
            request: Arc::new(request),
            profile,
            required,
            flow,
            cancelled: Cancellation::default(),
            changed: tokio::sync::Notify::new(),
        });
        operations.bytes += bytes;
        operations
            .streams
            .insert(operation.request.request_id.clone(), operation.clone());
        Ok(TcpAdmission::New(PendingTcp {
            session: self.clone(),
            operation,
            transferred: false,
        }))
    }

    pub(super) fn tcp_operation(&self, id: &str) -> Result<Option<Arc<Operation>>> {
        self.check()?;
        Ok(self
            .core
            .operations
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .streams
            .get(id)
            .cloned())
    }
}

impl Drop for PendingTcp {
    fn drop(&mut self) {
        if !self.transferred {
            self.operation.finish(stream::Cause::AttachmentLost);
        }
    }
}

impl ConnectedTcp {
    pub fn opened(&self) -> Result<stream::Opened> {
        let now = Instant::now();
        if now >= self.timing.idle {
            self.operation.finish(stream::Cause::Timeout);
            return Err(ErrorCode::RequestConflict.into());
        }
        if let Err(error) = self.session.check() {
            self.operation.finish(stream::Cause::SessionEnded);
            return Err(error);
        }
        if self.operation.cancelled.is_cancelled() || terminal(self.operation.status()?.state) {
            return Err(ErrorCode::RequestConflict.into());
        }
        let mut details = self.details.clone();
        details.remaining_lifetime_ms = self
            .timing
            .lifetime
            .saturating_duration_since(now)
            .as_millis() as u64;
        if details.remaining_lifetime_ms == 0 {
            self.operation.finish(stream::Cause::Timeout);
            return Err(ErrorCode::RequestConflict.into());
        }
        Ok(details)
    }
}

impl Drop for ConnectedTcp {
    fn drop(&mut self) {
        self.watchdog.abort();
        self.operation.finish(stream::Cause::AttachmentLost);
    }
}
