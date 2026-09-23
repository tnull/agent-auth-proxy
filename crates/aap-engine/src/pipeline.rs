use super::observation::{StreamState, headers, request_headers};
use super::*;
use aap_auth::{PreparedKey, placeholders::PlaceholderRedactor, sanitize_response};
use aap_observe::{Data, Decision, Direction, Flow, FlowContext, Protocol, View};
use aap_policy::{Authentication, Target, requires_approval};
use aap_secrets::ItemRef;
use aap_transport::{Endpoint, Limits};
use aap_types::profile::ProviderKind;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::{Bytes, BytesMut};
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
        let (operation, existing) = self.track_operation(request)?;
        if existing {
            let status = operation.status()?;
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
        let mut guard = Guard {
            session: self.clone(),
            operation: operation.clone(),
            active: None,
            finished: false,
            dispatched: false,
            observed: Mutex::new(std::array::from_fn(|_| StreamState::default())),
            website: None,
            remote: None,
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
                let delivery_check = guard
                    .remote
                    .as_ref()
                    .map(|exchange| exchange.completion_check());
                let completion_check = guard
                    .remote
                    .as_ref()
                    .map(|exchange| exchange.completion_check());
                let cancellation = {
                    let operation = operation.clone();
                    let session = self.clone();
                    let binding = guard
                        .website
                        .as_ref()
                        .map(|exchange| exchange.binding.clone());
                    let remote = guard
                        .remote
                        .as_ref()
                        .map(|exchange| exchange.binding.clone());
                    let remote_deadline = remote
                        .as_ref()
                        .map(|binding| binding.deadline())
                        .transpose()?
                        .unwrap_or(deadline);
                    Box::pin(async move {
                        let website = async {
                            if let Some(binding) = binding {
                                tokio::select! { _ = binding.cancelled.cancelled() => {}, _ = tokio::time::sleep_until(binding.expires) => {} }
                            } else {
                                std::future::pending::<()>().await;
                            }
                        };
                        let remote = async {
                            if let Some(binding) = remote {
                                binding.cancelled.cancelled().await;
                            } else {
                                std::future::pending::<()>().await;
                            }
                        };
                        tokio::select! { _ = operation.cancelled.cancelled() => {}, _ = session.core.cancelled.cancelled() => {}, _ = tokio::time::sleep_until(deadline.min(remote_deadline)) => {}, _ = website => {}, _ = remote => {} }
                    }) as BoxFuture<'static, ()>
                };
                Ok(response.map(|body| {
                    TrackedBody {
                        body,
                        guard,
                        cancellation,
                        observer: PlaceholderRedactor::default(),
                        unobserved: BytesMut::new(),
                        eof: false,
                        observation_ended: false,
                        delivery_check,
                        completion_check,
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

    fn track_operation(&self, request: ExecuteRequest) -> Result<(Arc<Operation>, bool)> {
        let mut operations = self
            .core
            .operations
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        if operations.issuances.contains_key(&request.request_id)
            || operations.streams.contains_key(&request.request_id)
        {
            return Err(ErrorCode::RequestConflict.into());
        }
        if let Some(existing) = operations.items.get(&request.request_id) {
            if *existing.request != request {
                return Err(ErrorCode::RequestConflict.into());
            }
            return Ok((existing.clone(), true));
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
        if operations.len() >= 4096 || operations.bytes + bytes > 8 * 1024 * 1024 {
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
        Ok((operation, false))
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
        if let Authentication::Mcp { .. } = &profile.auth {
            return self
                .dispatch_remote(guard, deadline, profile, &target, body)
                .await;
        }
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
            self.approve_operation(guard, item_id, &metadata.lease, None, deadline)
                .await?;
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
        let snapshot = self
            .resolve_current(store.as_ref(), &reference, &metadata.lease)
            .await?;
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
        let mut placeholders = PlaceholderRedactor::default();
        for (chunk, end) in outgoing
            .body()
            .chunks(32 * 1024)
            .map(|chunk| (chunk, false))
            .chain(std::iter::once((&[][..], true)))
        {
            let (safe, _) = placeholders.feed(&outbound.feed(chunk, end)?, end)?;
            guard.content_both(Direction::Outbound, &safe)?;
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

pub(super) struct Guard {
    pub flow: Flow,
    session: Session,
    pub operation: Arc<Operation>,
    pub active: Option<OwnedSemaphorePermit>,
    finished: bool,
    pub dispatched: bool,
    pub observed: Mutex<[StreamState; 4]>,
    pub website: Option<super::website::Exchange>,
    pub remote: Option<super::remote_mcp::Exchange>,
    pub response_recorded: bool,
}
impl Guard {
    /// Internal protocol work receives the same tracking budgets and an
    /// independent observation flow; no child inherits dispatch authority.
    pub fn child(session: &Session, parent: &Operation, request: ExecuteRequest) -> Result<Self> {
        session.check()?;
        let flow = Flow::new(
            session.core.host.configuration.recorder.clone(),
            FlowContext {
                session_id: session.id().into(),
                request_id: Some(request.request_id.clone()),
                parent_request_id: Some(parent.request.request_id.clone()),
                policy_version: session
                    .core
                    .host
                    .configuration
                    .catalog
                    .configuration_revision,
                protocol: Protocol::Http1,
            },
            session.core.options.require_observation,
        )?;
        let (operation, existing) = session.track_operation(request)?;
        if existing {
            return Err(ErrorCode::RequestConflict.into());
        }
        let mut child = Self {
            session: session.clone(),
            operation,
            flow,
            active: None,
            finished: false,
            dispatched: false,
            observed: Mutex::new(std::array::from_fn(|_| StreamState::default())),
            website: None,
            remote: None,
            response_recorded: false,
        };
        if let Err(error) = child.record_both(Direction::Outbound, Data::FlowOpen {}) {
            child.fail(error.code);
            return Err(error);
        }
        Ok(child)
    }
    pub fn complete_local(&mut self, status: u16) -> Result<()> {
        self.session.check()?;
        if self.operation.cancelled.is_cancelled() {
            return Err(ErrorCode::RequestConflict.into());
        }
        self.finish_observation(true, None)?;
        self.operation
            .transition(OperationState::Completed, Some(status))?;
        self.finished = true;
        Ok(())
    }
    pub fn complete(&mut self) -> Result<()> {
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
            if let Some(exchange) = &self.remote {
                exchange.check()?;
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
            if let Some(exchange) = &mut self.remote {
                exchange.commit()?;
            }
            if let (Some(context), Some(exchange)) = (&mut context_state, &self.website) {
                context.status = exchange.final_state;
            }
            state.state = OperationState::Completed;
        }
        self.finished = true;
        Ok(())
    }
    pub fn fail(&mut self, reason: ErrorCode) {
        if self.finished {
            return;
        }
        if let Some(exchange) = &self.website {
            exchange.binding.invalidate(AuthState::Revoked);
        }
        if let Some(exchange) = &mut self.remote {
            exchange.abandon();
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
    observer: PlaceholderRedactor,
    unobserved: BytesMut,
    eof: bool,
    observation_ended: bool,
    delivery_check: Option<BoxFuture<'static, Result<()>>>,
    completion_check: Option<BoxFuture<'static, Result<()>>>,
}
impl TrackedBody {
    fn observe(&mut self, bytes: &[u8], end: bool) -> Result<Option<Bytes>> {
        self.unobserved.extend_from_slice(bytes);
        let (safe, consumed) = self.observer.feed(bytes, end)?;
        if consumed > self.unobserved.len() {
            return Err(ErrorCode::ObservationUnavailable.into());
        }
        // The original prefix becomes deliverable only after its sanitized
        // observation was accepted. Retain the undecided suffix (at most 305
        // bytes) rather than releasing data ahead of required observation.
        self.guard.content_both(Direction::Inbound, &safe)?;
        Ok((consumed != 0).then(|| self.unobserved.split_to(consumed).freeze()))
    }
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
        for _ in 0..16 {
            if this.cancellation.as_mut().poll(context).is_ready() {
                this.guard.fail(ErrorCode::OutcomeUnknown);
                return Poll::Ready(Some(Err(ErrorCode::OutcomeUnknown.into())));
            }
            if let Some(check) = &mut this.delivery_check {
                match check.as_mut().poll(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.guard.fail(error.code);
                        return Poll::Ready(Some(Err(error)));
                    }
                    Poll::Ready(Ok(())) => this.delivery_check = None,
                }
            }
            if this.eof {
                if !this.guard.response_recorded && !this.observation_ended {
                    this.observation_ended = true;
                    match this.observe(&[], true) {
                        Ok(Some(bytes)) => return Poll::Ready(Some(Ok(Frame::data(bytes)))),
                        Ok(None) => {}
                        Err(error) => {
                            this.guard.fail(error.code);
                            return Poll::Ready(Some(Err(error)));
                        }
                    }
                }
                if let Some(check) = &mut this.completion_check {
                    match check.as_mut().poll(context) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            this.guard.fail(error.code);
                            return Poll::Ready(Some(Err(error)));
                        }
                        Poll::Ready(Ok(())) => this.completion_check = None,
                    }
                }
                if let Err(error) = this.guard.complete() {
                    this.guard.fail(error.code);
                    return Poll::Ready(Some(Err(error)));
                }
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.body).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    if this.guard.response_recorded {
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    let Some(bytes) = frame.data_ref() else {
                        this.guard.fail(ErrorCode::InspectionUnavailable);
                        return Poll::Ready(Some(Err(ErrorCode::InspectionUnavailable.into())));
                    };
                    match this.observe(bytes, false) {
                        Ok(Some(bytes)) => return Poll::Ready(Some(Ok(Frame::data(bytes)))),
                        Ok(None) => {}
                        Err(error) => {
                            this.guard.fail(error.code);
                            return Poll::Ready(Some(Err(error)));
                        }
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    this.guard.fail(error.code);
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => this.eof = true,
                Poll::Pending => return Poll::Pending,
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }
    fn is_end_stream(&self) -> bool {
        self.guard.finished
    }
}
