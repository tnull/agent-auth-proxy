use super::*;
use aap_policy::{Authentication, Target};
use aap_types::proxy::{ConnectAuthority, ForwardRequest};

impl Session {
    pub(super) async fn admit_connect_inner(&self, authority: &str) -> Result<()> {
        self.check()?;
        let authority = ConnectAuthority::parse(authority)?;
        let origin = authority.origin();
        let configuration = &self.core.host.configuration;
        let profiles: Vec<_> = configuration
            .profiles
            .iter()
            .filter(|profile| {
                profile.origin == origin && self.core.options.resources.contains(&profile.id)
            })
            .collect();
        if profiles.is_empty() {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let _permit = self
            .core
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::LimitExceeded)?;
        let candidates = tokio::select! {
            biased;
            _ = self.core.cancelled.cancelled() => return Err(ErrorCode::SessionInvalid.into()),
            resolved=tokio::time::timeout_at(self.core.expires.min(Instant::now()+Duration::from_secs(10)),configuration.resolver.resolve(authority.host(),authority.port())) => resolved.map_err(|_|ErrorCode::UpstreamUnavailable)??,
        };
        self.check()?;
        if candidates.is_empty() || candidates.len() > 64 {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let addresses: Vec<_> = candidates.iter().map(|address| address.ip()).collect();
        if candidates
            .iter()
            .any(|address| address.port() != authority.port())
            || !profiles
                .iter()
                .any(|profile| profile.addresses.permits_all(&addresses))
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        aap_observe::Flow::new(
            configuration.recorder.clone(),
            aap_observe::FlowContext {
                session_id: self.id().into(),
                request_id: None,
                parent_request_id: None,
                policy_version: configuration.catalog.configuration_revision,
                protocol: aap_observe::Protocol::Tls,
            },
            self.core.options.require_observation,
        )?
        .record(
            aap_observe::Direction::Outbound,
            aap_observe::View::Agent,
            aap_observe::Inspection::MetadataOnly,
            aap_observe::Redaction::Complete,
            aap_observe::Data::ConnectAdmission {
                authority: authority.authority(),
            },
        )?;
        Ok(())
    }

    pub(super) async fn forward_inner(&self, request: ForwardRequest) -> Result<Response> {
        self.check()?;
        let target = Target::parse(&request.target)?;
        let configuration = &self.core.host.configuration;
        let explicit = match request.auth_context.as_deref() {
            Some(id) => {
                let binding = self.binding(id)?;
                binding.check()?;
                Some(binding)
            }
            None => None,
        };
        let mut profiles = configuration.profiles.iter().filter(|profile| {
            self.core.options.resources.contains(&profile.id)
                && explicit
                    .as_ref()
                    .is_none_or(|binding| binding.item.profile == profile.id)
                && profile.authorize(&request.method, &target, 0).is_ok()
        });
        let profile = profiles.next().ok_or(ErrorCode::PolicyDenied)?;
        if profiles.next().is_some() {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let mut context = request.auth_context;
        if context.is_none() && matches!(profile.auth, Authentication::Form { .. }) {
            // Transparent clients may use a context only when both the account
            // grant and currently usable context are unambiguous.
            let mut items = configuration.catalog.items.iter().filter(|item| {
                item.profile == profile.id
                    && self
                        .core
                        .options
                        .items
                        .as_ref()
                        .is_none_or(|ids| ids.contains(&item.item_id))
            });
            let item = items.next().ok_or(ErrorCode::PolicyDenied)?;
            if items.next().is_some() {
                return Err(ErrorCode::PolicyDenied.into());
            }
            let bindings: Vec<_> = self
                .core
                .vault
                .lock()
                .map_err(|_| ErrorCode::InternalError)?
                .contexts
                .values()
                .filter(|binding| binding.item.item_id == item.item_id)
                .cloned()
                .collect();
            for binding in bindings {
                match binding.check() {
                    Ok(()) => {
                        if context.is_some() {
                            return Err(ErrorCode::PolicyDenied.into());
                        }
                        context = Some(binding.id.clone());
                    }
                    Err(error) if error.code == ErrorCode::PlaceholderInvalid => {}
                    Err(error) => return Err(error),
                }
            }
            if context.is_none() {
                return Err(ErrorCode::PolicyDenied.into());
            }
        }
        self.execute_inner(ExecuteRequest {
            request_id: request.request_id,
            resource: profile.id.clone(),
            auth_context: context,
            method: request.method,
            target: request.target,
            headers: request.headers,
            body_base64: request.body_base64,
        })
        .await
    }
}
