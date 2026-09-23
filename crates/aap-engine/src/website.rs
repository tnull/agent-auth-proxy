use super::*;
use super::{pipeline::Guard, vault::Binding};
use aap_auth::{
    Redactor,
    login::{CsrfToken, ValidatedLogin, reserved},
    sanitize_response,
};
use aap_observe::{Data, Decision, Direction, View};
use aap_policy::{Authentication, Target, requires_approval};
use aap_secrets::ItemRef;
use aap_transport::{Endpoint, Limits};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use std::time::SystemTime;

pub(super) struct Exchange {
    pub binding: Arc<Binding>,
    pub final_state: AuthState,
    _permit: OwnedSemaphorePermit,
}
struct Work<'a> {
    binding: Arc<Binding>,
    profile: &'a ResourceProfile,
    target: &'a Target,
    body: Vec<u8>,
    parsed: Option<ValidatedLogin>,
    is_page: bool,
    is_login: bool,
}

impl Session {
    pub(super) async fn dispatch_website(
        &self,
        guard: &mut Guard,
        deadline: Instant,
        profile: &ResourceProfile,
        target: &Target,
        body: Vec<u8>,
    ) -> Result<Response> {
        let input = guard.operation.request.clone();
        let binding = self.binding(
            input
                .auth_context
                .as_deref()
                .ok_or(ErrorCode::PolicyDenied)?,
        )?;
        binding.check()?;
        if binding.item.profile != profile.id
            || !self.item_allowed(&binding.item)
            || reserved(&input.target)
            || input
                .headers
                .iter()
                .any(|(name, value)| reserved(name) || reserved(value))
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let Authentication::Form { login } = &profile.auth else {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        };
        let route = profile.authorize(&input.method, target, body.len())?;
        if route.streaming || route.max_response_bytes > 256 * 1024 || body.len() > 256 * 1024 {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        let permit = binding
            .exchange
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::AuthInProgress)?;
        let is_page = input.method == "GET" && target.as_str() == login.page;
        let is_login = input.method == "POST" && target.as_str() == login.target;
        let media = input
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str())
            .unwrap_or("");
        let (parsed, previous) = {
            let state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
            if !is_page && !is_login && state.status != AuthState::Authenticated {
                return Err(ErrorCode::AuthFailed.into());
            }
            let parsed = if is_login {
                Some(ValidatedLogin::parse(
                    login,
                    media,
                    &body,
                    state.values.as_ref().ok_or(ErrorCode::PlaceholderInvalid)?,
                    state.csrf.as_ref(),
                )?)
            } else {
                if is_page && !body.is_empty() {
                    return Err(ErrorCode::RequestInvalid.into());
                }
                if !body.is_empty() {
                    if media != "application/json" {
                        return Err(ErrorCode::AuthProfileUnsupported.into());
                    }
                    let value: serde_json::Value =
                        aap_types::json::decode(&body).map_err(|_| ErrorCode::RequestInvalid)?;
                    if reserved(
                        &serde_json::to_string(&value).map_err(|_| ErrorCode::RequestInvalid)?,
                    ) {
                        return Err(ErrorCode::PlaceholderInvalid.into());
                    }
                }
                None
            };
            (parsed, state.status)
        };
        guard.website = Some(Exchange {
            binding: binding.clone(),
            final_state: previous,
            _permit: permit,
        });
        if is_login {
            binding
                .state
                .lock()
                .map_err(|_| ErrorCode::InternalError)?
                .status = AuthState::Authenticating;
        }
        let work = Work {
            binding: binding.clone(),
            profile,
            target,
            body,
            parsed,
            is_page,
            is_login,
        };
        let deadline = deadline.min(binding.expires);
        tokio::select! {
            biased;
            _ = binding.cancelled.cancelled() => Err(ErrorCode::PlaceholderInvalid.into()),
            result = tokio::time::timeout_at(deadline, self.website_exchange(guard,work,deadline)) => result.unwrap_or_else(|_| Err(ErrorCode::OutcomeUnknown.into())),
        }
    }
    async fn website_exchange(
        &self,
        guard: &mut Guard,
        work: Work<'_>,
        deadline: Instant,
    ) -> Result<Response> {
        let Work {
            binding,
            profile,
            target,
            body,
            parsed,
            is_page,
            is_login,
        } = work;
        let configuration = &self.core.host.configuration;
        let input = guard.operation.request.clone();
        let route = profile.authorize(&input.method, target, body.len())?;
        let Authentication::Form { login } = &profile.auth else {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        };
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
        self.revalidate_binding(&binding).await?;
        if requires_approval(
            configuration.require_approval,
            self.core.options.require_approval,
            route.require_approval,
            binding.item.approval,
            is_login,
        ) {
            self.approve_website(guard, &binding, deadline).await?;
        }
        self.revalidate_binding(&binding).await?;
        guard.active = Some(
            self.core
                .active
                .clone()
                .try_acquire_owned()
                .map_err(|_| ErrorCode::LimitExceeded)?,
        );
        let agent_body = match &parsed {
            Some(parsed) => parsed.observation()?,
            None => Bytes::copy_from_slice(&body),
        };
        let body = if let Some(parsed) = parsed {
            self.login_attempt(&binding.item.item_id)?;
            let store = configuration
                .stores
                .get(&binding.item.credential.store)
                .ok_or(ErrorCode::VaultUnavailable)?;
            let reference = ItemRef::new(binding.item.credential.key.clone())?;
            let snapshot = self
                .resolve_current(store.as_ref(), &reference, &binding.lease)
                .await?;
            let (body, redactor) = parsed.substitute(&snapshot)?;
            let mut state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
            state.template = state.template.merged(&redactor)?;
            body
        } else {
            Bytes::from(body)
        };
        let (cookie, outbound_template) = {
            let mut state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
            let values = state.values.as_ref().ok_or(ErrorCode::PlaceholderInvalid)?;
            let mut placeholders = vec![values.username().as_bytes(), values.password().as_bytes()];
            if let Some(csrf) = &state.csrf {
                placeholders.push(csrf.placeholder().as_bytes());
            }
            let template = state.template.merged(&Redactor::new(&placeholders)?)?;
            (state.jar.header(target, SystemTime::now())?, template)
        };
        let inserted = is_login || cookie.is_some();
        let mut outgoing = http::Request::builder()
            .method(input.method.as_str())
            .uri(target.as_str());
        for (name, value) in &input.headers {
            outgoing = outgoing.header(name, value);
        }
        if let Some(cookie) = cookie {
            outgoing = outgoing.header("cookie", cookie);
        }
        let outgoing = outgoing.body(body).map_err(|_| ErrorCode::RequestInvalid)?;
        guard.record_view(
            Direction::Outbound,
            View::Upstream,
            Data::RequestStart {
                method: input.method.clone(),
                target: format!("{}{}", profile.origin, target.path()),
                headers: super::observation::headers(outgoing.headers()),
            },
        )?;
        guard.content(
            Direction::Outbound,
            View::Agent,
            &redact(&mut outbound_template.fresh(), &agent_body)?,
        )?;
        guard.content(
            Direction::Outbound,
            View::Upstream,
            &redact(&mut outbound_template.fresh(), outgoing.body())?,
        )?;
        guard.record_both(
            Direction::Outbound,
            Data::AuthTransition {
                item_id: binding.item.item_id.clone(),
                inserted,
            },
        )?;
        guard.end_content(Direction::Outbound, &[View::Agent, View::Upstream])?;
        self.revalidate_binding(&binding).await?;
        guard.record_both(
            Direction::Outbound,
            Data::PolicyDecision {
                decision: Decision::Allow,
                reason: None,
            },
        )?;
        guard.operation.transition(OperationState::Ready, None)?;
        guard.begin_dispatch()?;
        let response = configuration
            .transport
            .execute(
                endpoint,
                outgoing,
                Limits {
                    max_request_bytes: route.max_request_bytes,
                    max_response_bytes: route.max_response_bytes,
                    total_timeout: deadline.saturating_duration_since(Instant::now()),
                    ..Limits::default()
                },
                guard.operation.cancelled.clone(),
            )
            .await?;
        let (mut parts, body) = response.into_parts();
        guard.record_view(
            Direction::Inbound,
            View::Upstream,
            Data::ResponseStart {
                status: parts.status.as_u16(),
                headers: super::observation::headers(&parts.headers),
            },
        )?;
        if parts.headers.get_all("content-type").iter().count() != 1
            || parts
                .headers
                .get("content-type")
                .is_none_or(|media| media != "application/json")
            || parts
                .headers
                .get("content-encoding")
                .is_some_and(|encoding| encoding != "identity")
        {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        let collected = Limited::new(body, route.max_response_bytes.min(256 * 1024))
            .collect()
            .await
            .map_err(|_| ErrorCode::OutcomeUnknown)?;
        if collected.trailers().is_some() {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        let mut bytes = collected.to_bytes();
        let upstream_bytes = bytes.clone();
        self.revalidate_binding(&binding).await?;
        let (template, observer) = {
            let mut state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
            if binding.cancelled.is_cancelled() || binding.expires <= Instant::now() {
                return Err(ErrorCode::PlaceholderInvalid.into());
            }
            let cookies = state
                .jar
                .capture(target, &mut parts.headers, SystemTime::now())?;
            state.template = state.template.merged(&cookies)?;
            if parts.status.is_redirection()
                && (!is_login
                    || parts.status != http::StatusCode::SEE_OTHER
                    || login.post_login_redirect.is_none())
            {
                return Err(ErrorCode::AuthProfileUnsupported.into());
            }
            let parsed: serde_json::Value =
                aap_types::json::decode(&bytes).map_err(|_| ErrorCode::InspectionUnavailable)?;
            if is_page && let Some(csrf) = &login.csrf {
                let (token, page) = CsrfToken::from_page(csrf, &bytes)?;
                state.template = state.template.merged(&token.redactor()?)?;
                state.csrf = Some(token);
                bytes = page;
            }
            if is_login {
                let success = parts.status.as_u16() == login.success.status
                    && parsed.pointer(&login.success.json_pointer) == Some(&login.success.expected)
                    && state
                        .jar
                        .has_all(&login.success.cookie_names, SystemTime::now())?;
                guard
                    .website
                    .as_mut()
                    .ok_or(ErrorCode::InternalError)?
                    .final_state = if success {
                    AuthState::Authenticated
                } else {
                    AuthState::Unauthenticated
                };
                if !success {
                    state.jar.clear();
                    state.csrf = None;
                    if parts.status.is_redirection() {
                        return Err(ErrorCode::AuthFailed.into());
                    }
                }
            } else if matches!(parts.status.as_u16(), 401 | 403) {
                state.jar.clear();
                state.csrf = None;
                guard
                    .website
                    .as_mut()
                    .ok_or(ErrorCode::InternalError)?
                    .final_state = AuthState::Unauthenticated;
            }
            let values = state.values.as_ref().ok_or(ErrorCode::PlaceholderInvalid)?;
            let mut private = vec![values.username().as_bytes(), values.password().as_bytes()];
            if let Some(csrf) = &state.csrf {
                private.push(csrf.placeholder().as_bytes());
            }
            (state.template.fresh(), Redactor::new(&private)?)
        };
        let upstream_observed = redact(&mut template.merged(&observer)?, &upstream_bytes)?;
        let private_response = http::Response::from_parts(
            parts,
            Full::new(bytes)
                .map_err(|never| match never {})
                .boxed_unsync(),
        );
        let response = if private_response.status().is_redirection() {
            aap_auth::sanitize_login_redirect(
                private_response,
                template,
                login
                    .post_login_redirect
                    .as_deref()
                    .ok_or(ErrorCode::AuthProfileUnsupported)?,
            )?
        } else {
            sanitize_response(private_response, template)?
        };
        let (parts, body) = response.into_parts();
        let bytes = Limited::new(body, route.max_response_bytes.min(256 * 1024))
            .collect()
            .await
            .map_err(|_| ErrorCode::InspectionUnavailable)?
            .to_bytes();
        // Website responses are completely inspected before delivery. Record the
        // additional placeholder-redacted view before releasing any agent byte.
        let mut observer = observer;
        let observed = redact(&mut observer, &bytes)?;
        guard.record(
            Direction::Inbound,
            Data::ResponseStart {
                status: parts.status.as_u16(),
                headers: super::observation::headers(&parts.headers),
            },
        )?;
        guard.content(Direction::Inbound, View::Upstream, &upstream_observed)?;
        guard.content(Direction::Inbound, View::Agent, &observed)?;
        guard.response_recorded = true;
        guard
            .operation
            .transition(OperationState::Dispatching, Some(parts.status.as_u16()))?;
        Ok(http::Response::from_parts(
            parts,
            Full::new(bytes)
                .map_err(|never| match never {})
                .boxed_unsync(),
        ))
    }
    async fn approve_website(
        &self,
        guard: &Guard,
        binding: &Binding,
        deadline: Instant,
    ) -> Result<()> {
        self.approve_operation(guard, &binding.item.item_id, &binding.lease, None, deadline)
            .await
    }
    fn login_attempt(&self, item: &str) -> Result<()> {
        let now = Instant::now();
        let age = Duration::from_secs(600);
        let mut vault = self
            .core
            .vault
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        let local = vault.attempts.entry(item.to_owned()).or_default();
        local.retain(|previous| now.duration_since(*previous) < age);
        let mut global = self
            .core
            .host
            .login_attempts
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        let global = global.entry(item.to_owned()).or_default();
        global.retain(|previous| now.duration_since(*previous) < age);
        if local.len() >= 5 || global.len() >= 20 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        local.push(now);
        global.push(now);
        Ok(())
    }
}
fn redact(redactor: &mut Redactor, body: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut placeholders = aap_auth::placeholders::PlaceholderRedactor::default();
    for (chunk, end) in body
        .chunks(32 * 1024)
        .map(|chunk| (chunk, false))
        .chain(std::iter::once((&[][..], true)))
    {
        let (safe, _) = placeholders.feed(&redactor.feed(chunk, end)?, end)?;
        output.extend(safe);
        if output.len() > 256 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
    }
    Ok(output)
}
