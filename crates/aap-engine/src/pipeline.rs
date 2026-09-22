use super::observation::{StreamState, headers, request_headers};
use super::*;
use aap_auth::{PreparedKey, sanitize_response};
use aap_observe::{Data, Decision, Direction, Flow, FlowContext, Protocol, View};
use aap_policy::{Authentication, Target, requires_approval};
use aap_secrets::ItemRef;
use aap_transport::{Endpoint, Limits};
use aap_types::profile::ProviderKind;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body::{Body as BodyTrait, Frame};
use http_body_util::{BodyExt, Full};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

impl Session {
    pub(super) async fn execute_inner(&self, request: ExecuteRequest) -> Result<Response> {
        self.check()?;
        if !aap_types::ids::valid_id(&request.request_id, 16) {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let flow = Flow::new(
            self.core.host.configuration.recorder.clone(),
            FlowContext {
                session_id: self.id().into(),
                request_id: Some(request.request_id.clone()),
                parent_request_id: None,
                policy_version: self.core.host.configuration.catalog.configuration_revision,
                protocol: Protocol::Http1,
            },
            self.core.options.require_observation,
        )?;
        let operation = {
            let mut operations = self
                .core
                .operations
                .lock()
                .map_err(|_| ErrorCode::InternalError)?;
            if operations.issuances.contains_key(&request.request_id) {
                return Err(ErrorCode::RequestConflict.into());
            }
            if let Some(existing) = operations.items.get(&request.request_id) {
                if *existing.request != request {
                    return Err(ErrorCode::RequestConflict.into());
                }
                let status = existing.status()?;
                return http::Response::builder()
                    .status(if terminal(status.state) { 200 } else { 202 })
                    .header("content-type", "application/json")
                    .header("x-aap-operation-state", "existing")
                    .body(
                        Full::new(Bytes::from(
                            serde_json::to_vec(&status).map_err(|_| ErrorCode::InternalError)?,
                        ))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                    )
                    .map_err(|_| ErrorCode::InternalError.into());
            }
            if request.body_base64.len() > 1_398_104
                || request.headers.len() > 64
                || request.target.len() > 16_384
                || request.resource.len() > 64
                || request.method.len() > 16
                || request
                    .auth_context
                    .as_ref()
                    .is_some_and(|context| context.len() > 64)
                || request
                    .headers
                    .iter()
                    .map(|(name, value)| name.len() + value.len())
                    .sum::<usize>()
                    > 65_536
            {
                return Err(ErrorCode::LimitExceeded.into());
            }
            let bytes = serde_json::to_vec(&request)
                .map_err(|_| ErrorCode::RequestInvalid)?
                .len()
                + 512;
            if operations.items.len() + operations.issuances.len() >= 4096
                || operations.bytes + bytes > 8 * 1024 * 1024
            {
                return Err(ErrorCode::LimitExceeded.into());
            }
            self.core
                .host
                .operation_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes)
                        .filter(|next| *next <= 64 * 1024 * 1024)
                })
                .map_err(|_| ErrorCode::LimitExceeded)?;
            let operation = Arc::new(Operation {
                state: Mutex::new(OperationStatus {
                    request_id: request.request_id.clone(),
                    state: OperationState::Received,
                    status: None,
                }),
                request: Arc::new(request),
                cancelled: Cancellation::default(),
            });
            operations.bytes += bytes;
            operations
                .items
                .insert(operation.request.request_id.clone(), operation.clone());
            operation
        };
        let mut guard = Guard {
            session: self.clone(),
            operation: operation.clone(),
            active: None,
            finished: false,
            dispatched: false,
            observed: Mutex::new(std::array::from_fn(|_| StreamState::default())),
            website: None,
            response_recorded: false,
            flow,
        };
        if let Err(error) = guard.record_both(Direction::Outbound, Data::FlowOpen {}) {
            guard.fail(error.code);
            return Err(error.for_request(&operation.request.request_id));
        }
        let deadline = self
            .core
            .expires
            .min(Instant::now() + Duration::from_secs(600));
        let prepared = tokio::select! {
            biased;
            _ = self.core.cancelled.cancelled() => Err(ErrorCode::SessionInvalid.into()),
            _ = operation.cancelled.cancelled() => Err(ErrorCode::RequestConflict.into()),
            result = tokio::time::timeout_at(deadline, self.dispatch(&mut guard, deadline)) => result.unwrap_or_else(|_| Err(ErrorCode::OutcomeUnknown.into())),
        };
        match prepared {
            Ok(response) => {
                let cancellation = {
                    let operation = operation.clone();
                    let session = self.clone();
                    let binding = guard
                        .website
                        .as_ref()
                        .map(|exchange| exchange.binding.clone());
                    Box::pin(async move {
                        let website = async {
                            if let Some(binding) = binding {
                                tokio::select! { _ = binding.cancelled.cancelled() => {}, _ = tokio::time::sleep_until(binding.expires) => {} }
                            } else {
                                std::future::pending::<()>().await;
                            }
                        };
                        tokio::select! { _ = operation.cancelled.cancelled() => {}, _ = session.core.cancelled.cancelled() => {}, _ = tokio::time::sleep_until(deadline) => {}, _ = website => {} }
                    }) as BoxFuture<'static, ()>
                };
                Ok(response.map(|body| {
                    TrackedBody {
                        body,
                        guard,
                        cancellation,
                    }
                    .boxed_unsync()
                }))
            }
            Err(error) => {
                guard.fail(error.code);
                Err(error.for_request(&operation.request.request_id))
            }
        }
    }

    async fn dispatch(&self, guard: &mut Guard, deadline: Instant) -> Result<Response> {
        let configuration = &self.core.host.configuration;
        let request = &guard.operation.request;
        if !self.core.options.resources.contains(&request.resource) {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let profile = configuration
            .profiles
            .iter()
            .find(|profile| profile.id == request.resource)
            .ok_or(ErrorCode::PolicyDenied)?;
        let target = Target::parse(&request.target)?;
        let body = STANDARD
            .decode(&request.body_base64)
            .map_err(|_| ErrorCode::RequestInvalid)?;
        if STANDARD.encode(&body) != request.body_base64 {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let route = profile.authorize(&request.method, &target, body.len())?;
        route.authorize_headers(&request.headers)?;
        if let Authentication::Form { .. } = &profile.auth {
            return self
                .dispatch_website(guard, deadline, profile, &target, body)
                .await;
        }
        if request.auth_context.is_some() {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let Authentication::ApiKey {
            item_id,
            header,
            prefix,
            provider,
        } = &profile.auth
        else {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        };
        if *provider == ProviderKind::AnthropicMessages
            && request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("anthropic-version"))
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        if *provider != ProviderKind::Generic
            && !request.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("content-type") && value == "application/json"
            })
        {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        configuration.inspector.inspect(*provider, &body)?;
        drop(body);
        let item = configuration
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
                method: request.method.clone(),
                target: format!("{}{}", profile.origin, target.path()),
                headers: request_headers(&request.headers),
            },
        )?;
        let addresses = configuration
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
        let store = configuration
            .stores
            .get(&item.credential.store)
            .ok_or(ErrorCode::VaultUnavailable)?;
        let reference = ItemRef::new(item.credential.key.clone())?;
        let metadata = store.metadata(&reference).await?;
        if requires_approval(
            configuration.require_approval,
            self.core.options.require_approval,
            route.require_approval,
            item.approval,
            true,
        ) {
            let provider = configuration
                .approval
                .as_ref()
                .ok_or(ErrorCode::InteractionUnavailable)?;
            let _pending = self
                .core
                .pending
                .clone()
                .try_acquire_owned()
                .map_err(|_| ErrorCode::LimitExceeded)?;
            let retained = request.body_base64.len()
                + request.target.len()
                + 1024
                + request
                    .headers
                    .iter()
                    .map(|(name, value)| name.len() + value.len())
                    .sum::<usize>();
            self.core
                .pending_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(retained)
                        .filter(|next| *next <= 4 * 1024 * 1024)
                })
                .map_err(|_| ErrorCode::LimitExceeded)?;
            let _retention = PendingRetention {
                used: &self.core.pending_bytes,
                retained,
            };
            let expires = deadline.min(Instant::now() + Duration::from_secs(300));
            let approval = Arc::new(ApprovalRequest {
                daemon_epoch: self.core.host.epoch.clone(),
                session_id: self.id().into(),
                approval_id: aap_types::ids::random_id(32).map_err(|_| ErrorCode::InternalError)?,
                configuration_revision: configuration.catalog.configuration_revision,
                item_id: item_id.clone(),
                operation: request.clone(),
                credential_lease: metadata.lease.clone(),
                expires_at: expires.into_std(),
            });
            guard
                .operation
                .transition(OperationState::PendingApproval, None)?;
            guard.record_both(
                Direction::Outbound,
                Data::PolicyDecision {
                    decision: Decision::Pending,
                    reason: None,
                },
            )?;
            let approved = tokio::time::timeout_at(
                expires,
                provider.approve(approval, guard.operation.cancelled.clone()),
            )
            .await
            .map_err(|_| ErrorCode::InteractionUnavailable)??;
            if !approved {
                return Err(ErrorCode::PolicyDenied.into());
            }
        }
        self.check()?;
        let body = STANDARD
            .decode(&request.body_base64)
            .map_err(|_| ErrorCode::RequestInvalid)?;
        guard.active = Some(
            self.core
                .active
                .clone()
                .try_acquire_owned()
                .map_err(|_| ErrorCode::LimitExceeded)?,
        );
        store.revalidate(&reference, &metadata.lease).await?;
        let snapshot = store.resolve(&reference, &metadata.lease).await?;
        let key = PreparedKey::new(&snapshot, prefix)?;
        let mut outgoing = http::Request::builder()
            .method(request.method.as_str())
            .uri(target.as_str());
        for (name, value) in &request.headers {
            outgoing = outgoing.header(name, value);
        }
        if *provider == ProviderKind::AnthropicMessages {
            outgoing = outgoing.header("anthropic-version", "2023-06-01");
        }
        let mut outgoing = outgoing
            .body(Bytes::from(body))
            .map_err(|_| ErrorCode::RequestInvalid)?;
        let redactor = key.inject(&mut outgoing, header)?;
        guard.record_view(
            Direction::Outbound,
            View::Upstream,
            Data::RequestStart {
                method: request.method.clone(),
                target: format!("{}{}", profile.origin, target.path()),
                headers: headers(outgoing.headers()),
            },
        )?;
        let mut outbound = redactor.fresh();
        for (chunk, end) in outgoing
            .body()
            .chunks(32 * 1024)
            .map(|chunk| (chunk, false))
            .chain(std::iter::once((&[][..], true)))
        {
            guard.content_both(Direction::Outbound, &outbound.feed(chunk, end)?)?;
        }
        guard.record_both(
            Direction::Outbound,
            Data::AuthTransition {
                item_id: item_id.clone(),
                inserted: true,
            },
        )?;
        guard.end_content(Direction::Outbound, &[View::Agent, View::Upstream])?;
        store.revalidate(&reference, &metadata.lease).await?;
        self.check()?;
        if metadata
            .valid_until
            .is_some_and(|expiry| expiry <= std::time::Instant::now())
        {
            return Err(ErrorCode::VaultUnavailable.into());
        }
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
        let limits = Limits {
            max_request_bytes: route.max_request_bytes,
            max_response_bytes: route.max_response_bytes,
            total_timeout: deadline.saturating_duration_since(Instant::now()),
            ..Limits::default()
        };
        let response = configuration
            .transport
            .execute(
                endpoint,
                outgoing,
                limits,
                guard.operation.cancelled.clone(),
            )
            .await?;
        guard.record_view(
            Direction::Inbound,
            View::Upstream,
            Data::ResponseStart {
                status: response.status().as_u16(),
                headers: headers(response.headers()),
            },
        )?;
        let response = sanitize_response(response, redactor)?;
        guard.record(
            Direction::Inbound,
            Data::ResponseStart {
                status: response.status().as_u16(),
                headers: headers(response.headers()),
            },
        )?;
        guard.operation.transition(
            OperationState::Dispatching,
            Some(response.status().as_u16()),
        )?;
        Ok(response)
    }
}

struct PendingRetention<'a> {
    used: &'a AtomicUsize,
    retained: usize,
}
impl Drop for PendingRetention<'_> {
    fn drop(&mut self) {
        self.used.fetch_sub(self.retained, Ordering::AcqRel);
    }
}

pub(super) struct Guard {
    pub flow: Flow,
    session: Session,
    pub operation: Arc<Operation>,
    pub active: Option<OwnedSemaphorePermit>,
    finished: bool,
    pub dispatched: bool,
    pub observed: Mutex<[StreamState; 4]>,
    pub website: Option<super::website::Exchange>,
    pub response_recorded: bool,
}
impl Guard {
    fn complete(&mut self) -> Result<()> {
        {
            let mut state = self
                .operation
                .state
                .lock()
                .map_err(|_| ErrorCode::InternalError)?;
            if self.session.check().is_err()
                || self.operation.cancelled.is_cancelled()
                || state.state != OperationState::Dispatching
            {
                return Err(ErrorCode::OutcomeUnknown.into());
            }
            if let Some(exchange) = &self.website {
                exchange.binding.check()?;
            }
            let mut context_state = self
                .website
                .as_ref()
                .map(|exchange| {
                    exchange
                        .binding
                        .state
                        .lock()
                        .map_err(|_| ErrorCode::InternalError)
                })
                .transpose()?;
            if self.website.as_ref().is_some_and(|exchange| {
                exchange.binding.cancelled.is_cancelled()
                    || exchange.binding.expires <= Instant::now()
            }) {
                return Err(ErrorCode::OutcomeUnknown.into());
            }
            self.finish_observation(true, None)?;
            if let (Some(context), Some(exchange)) = (&mut context_state, &self.website) {
                context.status = exchange.final_state;
            }
            state.state = OperationState::Completed;
        }
        self.finished = true;
        Ok(())
    }
    fn fail(&mut self, reason: ErrorCode) {
        if self.finished {
            return;
        }
        if let Some(exchange) = &self.website {
            exchange.binding.invalidate(AuthState::Revoked);
        }
        let state = if self.dispatched {
            OperationState::OutcomeUnknown
        } else if reason == ErrorCode::PolicyDenied {
            OperationState::Denied
        } else {
            OperationState::Failed
        };
        let _ = self.operation.transition(state, None);
        self.operation.cancelled.cancel();
        if !self.dispatched {
            let _ = self.record_both(
                Direction::Outbound,
                Data::PolicyDecision {
                    decision: Decision::Deny,
                    reason: Some(reason),
                },
            );
        }
        let _ = self.finish_observation(false, Some(reason));
        self.finished = true;
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.finished {
            self.operation.cancel();
            self.fail(if self.dispatched {
                ErrorCode::OutcomeUnknown
            } else {
                ErrorCode::RequestConflict
            });
        }
    }
}
struct TrackedBody {
    body: aap_types::Body,
    guard: Guard,
    cancellation: BoxFuture<'static, ()>,
}
impl BodyTrait for TrackedBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        if this.guard.finished {
            return Poll::Ready(None);
        }
        if this.cancellation.as_mut().poll(context).is_ready() {
            this.guard.fail(ErrorCode::OutcomeUnknown);
            return Poll::Ready(Some(Err(ErrorCode::OutcomeUnknown.into())));
        }
        match Pin::new(&mut this.body).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref()
                    && !this.guard.response_recorded
                    && let Err(error) = this.guard.content_both(Direction::Inbound, bytes)
                {
                    this.guard.fail(error.code);
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.guard.fail(error.code);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if let Err(error) = this.guard.complete() {
                    this.guard.fail(error.code);
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.guard.finished
    }
}
