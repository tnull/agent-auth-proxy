//! Session-owned remote protocol state; all I/O uses the admitted connector.
use super::{pipeline::Guard, *};
use aap_auth::{PreparedKey, Redactor, placeholders::PlaceholderRedactor};
use aap_mcp_upstream::{Completion, Context, Method, Request, State};
use aap_observe::{Data, Decision, Direction, View};
use aap_policy::{Authentication, Target, requires_approval};
use aap_secrets::{ItemMetadata, ItemRef, Lease};
use aap_transport::{Endpoint, Limits};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::sync::atomic::AtomicBool;

mod cancellation;
mod cleanup;
mod control;

#[derive(Default)]
pub(super) struct Vault {
    contexts: Vec<(String, Arc<Binding>)>,
}
pub(super) struct Binding {
    pub id: String,
    state: Mutex<Context>,
    lease: Lease,
    reference: ItemRef,
    store: Arc<dyn SecretStore>,
    pub expires: Instant,
    handshake: Instant,
    pub cancelled: Cancellation,
    closing: AtomicBool,
    _permit: OwnedSemaphorePermit,
}
struct Reservation {
    _local: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}
pub(super) struct Exchange {
    pub binding: Arc<Binding>,
    exchange: Option<aap_mcp_upstream::Exchange>,
    completion: Option<Completion>,
    _request: Reservation,
    response: Option<Reservation>,
}
impl Binding {
    fn invalidate(&self) {
        self.cancelled.cancel();
        if let Ok(mut state) = self.state.lock() {
            state.invalidate();
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.cancelled.is_cancelled() || Instant::now() >= self.expires {
            self.invalidate();
            return Err(ErrorCode::SessionInvalid.into());
        }
        let state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .state(Instant::now().into_std());
        if matches!(state, State::Invalid | State::Closed) {
            self.cancelled.cancel();
            return Err(ErrorCode::SessionInvalid.into());
        }
        Ok(())
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.check()?;
        Ok(
            if self
                .state
                .lock()
                .map_err(|_| ErrorCode::InternalError)?
                .state(Instant::now().into_std())
                == State::Ready
            {
                self.expires
            } else {
                self.handshake.min(self.expires)
            },
        )
    }
    async fn revalidate(&self) -> Result<()> {
        self.check()?;
        if let Err(error) = self.store.revalidate(&self.reference, &self.lease).await {
            self.invalidate();
            return Err(error.into());
        }
        self.check()
    }
}
impl Exchange {
    pub fn check(&self) -> Result<()> {
        self.binding.check()?;
        self.binding
            .state
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .validate(
                self.exchange.as_ref().ok_or(ErrorCode::RequestConflict)?,
                Instant::now().into_std(),
            )
    }
    pub fn completion_check(&self) -> BoxFuture<'static, Result<()>> {
        let binding = self.binding.clone();
        Box::pin(async move { binding.revalidate().await })
    }
    pub fn commit(&mut self) -> Result<()> {
        self.check()?;
        self.binding
            .state
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .complete(
                self.exchange.take().ok_or(ErrorCode::RequestConflict)?,
                self.completion.take().ok_or(ErrorCode::RequestConflict)?,
                Instant::now().into_std(),
            )?;
        Ok(())
    }
    pub fn abandon(&mut self) {
        self.completion = None;
        if let Some(exchange) = self.exchange.take() {
            if let Ok(mut state) = self.binding.state.lock() {
                state.abandon(exchange);
                if matches!(
                    state.state(Instant::now().into_std()),
                    State::Invalid | State::Closed
                ) {
                    self.binding.cancelled.cancel();
                }
            } else {
                self.binding.cancelled.cancel();
            }
        }
    }
}
impl Drop for Exchange {
    fn drop(&mut self) {
        self.abandon();
    }
}

impl Session {
    pub(super) fn invalidate_remote(&self, resource: Option<&str>) -> Result<()> {
        let vault = self
            .core
            .remote
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        for (name, binding) in &vault.contexts {
            if resource.is_none_or(|resource| name == resource) {
                binding.invalidate();
            }
        }
        Ok(())
    }
    fn reserve_remote(&self, bytes: usize) -> Result<Reservation> {
        let bytes = u32::try_from(bytes).map_err(|_| ErrorCode::LimitExceeded)?;
        let global = self
            .core
            .host
            .remote_buffers
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| ErrorCode::LimitExceeded)?;
        let local = self
            .core
            .remote_buffers
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| ErrorCode::LimitExceeded)?;
        Ok(Reservation {
            _local: local,
            _global: global,
        })
    }
    fn prepare_remote(
        &self,
        input: &ExecuteRequest,
        message: Request,
        metadata: &ItemMetadata,
        reference: ItemRef,
        store: Arc<dyn SecretStore>,
        reservation: Reservation,
    ) -> Result<Exchange> {
        let resource = input.resource.as_str();
        let mut vault = self
            .core
            .remote
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        let current = vault
            .contexts
            .iter()
            .rev()
            .find(|(name, _)| name == resource)
            .map(|(_, binding)| binding.clone());
        if current
            .as_ref()
            .is_some_and(|binding| binding.closing.load(Ordering::Acquire))
        {
            return Err(ErrorCode::RequestConflict.into());
        }
        if let Some(binding) = &current
            && binding.lease != metadata.lease
        {
            binding.invalidate();
        }
        let binding = if let Some(binding) = current.filter(|binding| binding.check().is_ok()) {
            binding
        } else {
            if message.method() != Method::Initialize {
                return Err(ErrorCode::RequestConflict.into());
            }
            if vault.contexts.len() >= 16 {
                return Err(ErrorCode::LimitExceeded.into());
            }
            let permit = self
                .core
                .host
                .contexts
                .clone()
                .try_acquire_owned()
                .map_err(|_| ErrorCode::LimitExceeded)?;
            let now = Instant::now();
            let expires = self.core.expires.min(now + Duration::from_secs(600)).min(
                metadata
                    .valid_until
                    .map(Instant::from_std)
                    .unwrap_or(self.core.expires),
            );
            let profile = self
                .core
                .host
                .remote_profiles
                .get(resource)
                .ok_or(ErrorCode::PolicyDenied)?
                .clone();
            let binding = Arc::new(Binding {
                id: aap_types::ids::random_id(16).map_err(|_| ErrorCode::InternalError)?,
                state: Mutex::new(Context::new(profile, now.into_std(), expires.into_std())?),
                lease: metadata.lease.clone(),
                reference,
                store,
                expires,
                handshake: now + Duration::from_secs(30),
                cancelled: Cancellation::default(),
                closing: AtomicBool::new(false),
                _permit: permit,
            });
            vault.contexts.push((resource.into(), binding.clone()));
            binding
        };
        let exchange = binding
            .state
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .begin(message, &input.request_id, Instant::now().into_std())?
            .ok_or(ErrorCode::RequestConflict)?;
        Ok(Exchange {
            binding,
            exchange: Some(exchange),
            completion: None,
            _request: reservation,
            response: None,
        })
    }

    pub(super) async fn dispatch_remote(
        &self,
        guard: &mut Guard,
        deadline: Instant,
        profile: &ResourceProfile,
        target: &Target,
        body: Vec<u8>,
    ) -> Result<Response> {
        let input = guard.operation.request.clone();
        let config = &self.core.host.configuration;
        if input.auth_context.is_some() {
            return Err(ErrorCode::PolicyDenied.into());
        }
        if !matches!(input.method.as_str(), "POST" | "DELETE") {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        let Authentication::Mcp {
            item_id,
            header,
            prefix,
            ..
        } = &profile.auth
        else {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        };
        for (name, value) in &input.headers {
            if (name.eq_ignore_ascii_case("content-type") && value != "application/json")
                || (name.eq_ignore_ascii_case("mcp-protocol-version")
                    && value != aap_types::mcp::VERSION)
                || (name.eq_ignore_ascii_case("accept")
                    && value != "application/json, text/event-stream")
            {
                return Err(ErrorCode::InspectionUnavailable.into());
            }
        }
        if input.method == "DELETE" {
            if !body.is_empty() {
                return Err(ErrorCode::RequestInvalid.into());
            }
            return self
                .close_remote_context(guard, profile, target, item_id, deadline)
                .await;
        }
        if !input
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        let route = profile.authorize(&input.method, target, body.len())?;
        let request_reservation = self.reserve_remote(body.len() * 2 + 64 * 1024)?;
        let compiled = self
            .core
            .host
            .remote_profiles
            .get(&profile.id)
            .ok_or(ErrorCode::PolicyDenied)?;
        let message = compiled.request(&body)?;
        let control = matches!(message.method(), Method::Ping | Method::Initialized);
        let item = config
            .catalog
            .items
            .iter()
            .find(|item| &item.item_id == item_id)
            .ok_or(ErrorCode::PolicyDenied)?;
        if !self.item_allowed(item) {
            return Err(ErrorCode::PolicyDenied.into());
        }
        guard
            .operation
            .transition(OperationState::Validated, None)?;
        guard.record(
            Direction::Outbound,
            Data::RequestStart {
                method: input.method.clone(),
                target: format!("{}{}", profile.origin, target.path()),
                headers: super::observation::request_headers(&input.headers),
            },
        )?;
        if message.method() == Method::Cancel {
            return self
                .cancel_remote_message(guard, profile, target, message, deadline)
                .await;
        }
        let store = config
            .stores
            .get(&item.credential.store)
            .ok_or(ErrorCode::VaultUnavailable)?
            .clone();
        let reference = ItemRef::new(item.credential.key.clone())?;
        let metadata = match store.metadata(&reference).await {
            Ok(metadata) => metadata,
            Err(error) => {
                self.invalidate_remote(Some(&profile.id))?;
                return Err(error.into());
            }
        };
        let exchange = self.prepare_remote(
            &input,
            message,
            &metadata,
            reference,
            store,
            request_reservation,
        )?;
        let binding = exchange.binding.clone();
        guard.remote = Some(exchange);
        let deadline = deadline.min(binding.deadline()?);
        let exchange = async {
            if requires_approval(
                config.require_approval,
                self.core.options.require_approval,
                route.require_approval,
                item.approval,
                true,
            ) {
                self.approve_operation(guard, item_id, &binding.lease, Some(&binding.id), deadline)
                    .await?;
            }
            self.check()?;
            binding.revalidate().await?;
            guard
                .remote
                .as_ref()
                .ok_or(ErrorCode::InternalError)?
                .check()?;
            guard.active = Some(
                if control {
                    &self.core.control
                } else {
                    &self.core.active
                }
                .clone()
                .try_acquire_owned()
                .map_err(|_| ErrorCode::LimitExceeded)?,
            );
            let maximum = if control {
                route.max_response_bytes.min(64 * 1024)
            } else {
                route.max_response_bytes
            };
            guard
                .remote
                .as_mut()
                .ok_or(ErrorCode::InternalError)?
                .response = Some(self.reserve_remote(maximum * 6)?);
            let addresses = config
                .resolver
                .resolve(
                    target.host().trim_start_matches('[').trim_end_matches(']'),
                    target.port(),
                )
                .await?;
            if addresses
                .iter()
                .any(|address| address.port() != target.port())
                || !profile.addresses.permits_all(
                    &addresses
                        .iter()
                        .map(|address| address.ip())
                        .collect::<Vec<_>>(),
                )
            {
                return Err(ErrorCode::PolicyDenied.into());
            }
            let endpoint = Endpoint::new(&profile.origin, addresses[0])?;
            let mut outgoing = {
                let remote = guard.remote.as_ref().ok_or(ErrorCode::InternalError)?;
                let prepared = binding
                    .state
                    .lock()
                    .map_err(|_| ErrorCode::InternalError)?
                    .outgoing(
                        remote.exchange.as_ref().ok_or(ErrorCode::RequestConflict)?,
                        Instant::now().into_std(),
                    )?;
                let mut request = http::Request::builder()
                    .method("POST")
                    .uri(target.as_str())
                    .body(Bytes::from(prepared.body))
                    .map_err(|_| ErrorCode::RequestInvalid)?;
                *request.headers_mut() = prepared.headers;
                request
            };
            let authenticated: Result<Redactor> = async {
                let snapshot = binding
                    .store
                    .resolve(&binding.reference, &binding.lease)
                    .await?;
                PreparedKey::new(&snapshot, prefix)?.inject(&mut outgoing, header)
            }
            .await;
            let redactor = match authenticated {
                Ok(redactor) => redactor,
                Err(error) => {
                    binding.invalidate();
                    return Err(error);
                }
            };
            guard.record_view(
                Direction::Outbound,
                View::Upstream,
                Data::RequestStart {
                    method: "POST".into(),
                    target: format!("{}{}", profile.origin, target.path()),
                    headers: super::observation::headers(outgoing.headers()),
                },
            )?;
            observe(guard, Direction::Outbound, View::Agent, &redactor, &body)?;
            observe(
                guard,
                Direction::Outbound,
                View::Upstream,
                &redactor,
                outgoing.body(),
            )?;
            guard.record_both(
                Direction::Outbound,
                Data::AuthTransition {
                    item_id: item_id.clone(),
                    inserted: true,
                },
            )?;
            guard.end_content(Direction::Outbound, &[View::Agent, View::Upstream])?;
            binding.revalidate().await?;
            self.check()?;
            guard
                .remote
                .as_ref()
                .ok_or(ErrorCode::InternalError)?
                .check()?;
            guard.record_both(
                Direction::Outbound,
                Data::PolicyDecision {
                    decision: Decision::Allow,
                    reason: None,
                },
            )?;
            guard.operation.transition(OperationState::Ready, None)?;
            guard
                .operation
                .transition(OperationState::Dispatching, None)?;
            guard.dispatched = true;
            let response = config
                .transport
                .execute(
                    endpoint,
                    outgoing,
                    Limits {
                        max_request_bytes: route.max_request_bytes,
                        max_response_bytes: maximum,
                        total_timeout: deadline.saturating_duration_since(Instant::now()),
                        ..Limits::default()
                    },
                    guard.operation.cancelled.clone(),
                )
                .await?;
            guard.record_view(
                Direction::Inbound,
                View::Upstream,
                Data::ResponseStart {
                    status: response.status().as_u16(),
                    headers: super::observation::headers(response.headers()),
                },
            )?;
            let mut decoder = {
                let remote = guard.remote.as_ref().ok_or(ErrorCode::InternalError)?;
                binding
                    .state
                    .lock()
                    .map_err(|_| ErrorCode::InternalError)?
                    .start_response(
                        remote.exchange.as_ref().ok_or(ErrorCode::RequestConflict)?,
                        response.status(),
                        response.headers(),
                        &redactor,
                        Instant::now().into_std(),
                    )?
            };
            let mut response_body = response.into_body();
            while let Some(frame) = response_body.frame().await {
                binding.check()?;
                let frame = frame?;
                let Some(data) = frame.data_ref() else {
                    binding.invalidate();
                    return Err(ErrorCode::InspectionUnavailable.into());
                };
                for chunk in data.chunks(aap_types::mcp::MAX_REQUEST) {
                    for ping in decoder.push(chunk)? {
                        let outgoing = {
                            let remote = guard.remote.as_ref().ok_or(ErrorCode::InternalError)?;
                            binding
                                .state
                                .lock()
                                .map_err(|_| ErrorCode::InternalError)?
                                .ping_reply(
                                    remote.exchange.as_ref().ok_or(ErrorCode::RequestConflict)?,
                                    &decoder,
                                    &ping,
                                    Instant::now().into_std(),
                                )?
                        };
                        self.reply_remote_ping(guard, profile, target, outgoing, deadline)
                            .await?;
                    }
                }
            }
            let completion = decoder.finish()?;
            binding.revalidate().await?;
            self.check()?;
            let safe = completion.response();
            let mut response = http::Response::builder().status(safe.status);
            if let Some(media) = safe.content_type {
                response = response.header("content-type", media);
            }
            let response = response
                .body(
                    Full::new(Bytes::copy_from_slice(&safe.body))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .map_err(|_| ErrorCode::InternalError)?;
            guard.record(
                Direction::Inbound,
                Data::ResponseStart {
                    status: response.status().as_u16(),
                    headers: super::observation::headers(response.headers()),
                },
            )?;
            // Structural sanitization is already complete; only additional
            // observation-only placeholder suppression runs here.
            for view in [View::Agent, View::Upstream] {
                observe(
                    guard,
                    Direction::Inbound,
                    view,
                    &Redactor::new(&[])?,
                    &safe.body,
                )?;
            }
            guard.response_recorded = true;
            guard.operation.transition(
                OperationState::Dispatching,
                Some(response.status().as_u16()),
            )?;
            guard
                .remote
                .as_mut()
                .ok_or(ErrorCode::InternalError)?
                .completion = Some(completion);
            Ok(response)
        };
        tokio::select! {
            biased;
            _ = binding.cancelled.cancelled()=>Err(ErrorCode::SessionInvalid.into()),
            result = tokio::time::timeout_at(deadline, exchange)=>result.unwrap_or_else(|_|Err(ErrorCode::OutcomeUnknown.into())),
        }
    }
}
fn empty_response(status: u16) -> Result<Response> {
    http::Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .map_err(|_| ErrorCode::InternalError.into())
}
fn observe(
    guard: &Guard,
    direction: Direction,
    view: View,
    template: &Redactor,
    body: &[u8],
) -> Result<()> {
    let mut secret = template.fresh();
    let mut placeholders = PlaceholderRedactor::default();
    for (chunk, end) in body
        .chunks(32 * 1024)
        .map(|chunk| (chunk, false))
        .chain(std::iter::once((&[][..], true)))
    {
        let (safe, _) = placeholders.feed(&secret.feed(chunk, end)?, end)?;
        guard.content(direction, view, &safe)?;
    }
    Ok(())
}
