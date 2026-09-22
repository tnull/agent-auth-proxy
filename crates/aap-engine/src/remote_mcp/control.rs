//! Control messages are separate admitted operations, never a second client.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

// Private server-selected IDs are not retained in operation DTOs or telemetry.
// Only the one-shot Outgoing from the protocol component contains the real ID.
const SAFE_PING_REPLY: &[u8] = br#"{"jsonrpc":"2.0","id":"[upstream-id-withheld]","result":{}}"#;
pub(super) const SAFE_CANCEL: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"[upstream-id-withheld]"}}"#;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Ping,
    Cancel,
}
pub(super) struct Control {
    pub binding: Arc<Binding>,
    pub outgoing: aap_mcp_upstream::Outgoing,
    pub kind: Kind,
}

impl Session {
    pub(super) async fn reply_remote_ping(
        &self,
        parent: &Guard,
        profile: &ResourceProfile,
        target: &Target,
        prepared: aap_mcp_upstream::Outgoing,
        deadline: Instant,
    ) -> Result<()> {
        let binding = parent
            .remote
            .as_ref()
            .ok_or(ErrorCode::InternalError)?
            .binding
            .clone();
        self.dispatch_remote_control(
            &parent.operation,
            profile,
            target,
            Control {
                binding,
                outgoing: prepared,
                kind: Kind::Ping,
            },
            deadline,
        )
        .await
    }

    pub(super) async fn dispatch_remote_control(
        &self,
        parent: &Operation,
        profile: &ResourceProfile,
        target: &Target,
        control: Control,
        deadline: Instant,
    ) -> Result<()> {
        let Control {
            binding,
            outgoing: prepared,
            kind,
        } = control;
        let safe_body = match kind {
            Kind::Ping => SAFE_PING_REPLY,
            Kind::Cancel => SAFE_CANCEL,
        };
        let mut child = Guard::child(
            self,
            parent,
            ExecuteRequest {
                request_id: aap_types::ids::random_id(16).map_err(|_| ErrorCode::InternalError)?,
                resource: profile.id.clone(),
                auth_context: None,
                method: "POST".into(),
                target: target.as_str().into(),
                headers: vec![("content-type".into(), "application/json".into())],
                body_base64: STANDARD.encode(safe_body),
            },
        )?;
        let config = &self.core.host.configuration;
        let Authentication::Mcp {
            item_id,
            header,
            prefix,
            ..
        } = &profile.auth
        else {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        };
        let child_cancelled = child.operation.cancelled.clone();
        let attempt = async {
            self.check()?;
            if !self.core.options.resources.contains(&profile.id) {
                return Err(ErrorCode::PolicyDenied.into());
            }
            let route = profile.authorize("POST", target, prepared.body.len())?;
            route.authorize_headers(&child.operation.request.headers)?;
            let item = config
                .catalog
                .items
                .iter()
                .find(|item| &item.item_id == item_id)
                .ok_or(ErrorCode::PolicyDenied)?;
            if !self.item_allowed(item) {
                return Err(ErrorCode::PolicyDenied.into());
            }
            child
                .operation
                .transition(OperationState::Validated, None)?;
            child.record(
                Direction::Outbound,
                Data::RequestStart {
                    method: "POST".into(),
                    target: target.as_str().into(),
                    headers: super::super::observation::request_headers(
                        &child.operation.request.headers,
                    ),
                },
            )?;
            // Approval of the parent does not cover another authenticated POST.
            // In particular, never hold the parent response open for human input.
            if requires_approval(
                config.require_approval,
                self.core.options.require_approval,
                route.require_approval,
                item.approval,
                true,
            ) {
                child.fail(ErrorCode::InteractionUnavailable);
                return Ok(());
            }
            binding.check()?;
            binding.revalidate().await?;
            child.active = Some(
                self.core
                    .control
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| ErrorCode::LimitExceeded)?,
            );
            let _buffers = self.reserve_remote(256 * 1024)?;
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
            let mut outgoing = http::Request::builder()
                .method("POST")
                .uri(target.as_str())
                .body(Bytes::from(prepared.body))
                .map_err(|_| ErrorCode::RequestInvalid)?;
            *outgoing.headers_mut() = prepared.headers;
            let authenticated: Result<()> = async {
                let snapshot = binding
                    .store
                    .resolve(&binding.reference, &binding.lease)
                    .await?;
                PreparedKey::new(&snapshot, prefix)?.inject(&mut outgoing, header)?;
                Ok(())
            }
            .await;
            if let Err(error) = authenticated {
                binding.invalidate();
                return Err(error);
            }
            child.record_view(
                Direction::Outbound,
                View::Upstream,
                Data::RequestStart {
                    method: "POST".into(),
                    target: target.as_str().into(),
                    headers: super::super::observation::headers(outgoing.headers()),
                },
            )?;
            child.content_both(Direction::Outbound, safe_body)?;
            child.record_both(
                Direction::Outbound,
                Data::AuthTransition {
                    item_id: item_id.clone(),
                    inserted: true,
                },
            )?;
            child.end_content(Direction::Outbound, &[View::Agent, View::Upstream])?;
            binding.revalidate().await?;
            self.check()?;
            binding.check()?;
            child.record_both(
                Direction::Outbound,
                Data::PolicyDecision {
                    decision: Decision::Allow,
                    reason: None,
                },
            )?;
            child.operation.transition(OperationState::Ready, None)?;
            child
                .operation
                .transition(OperationState::Dispatching, None)?;
            child.dispatched = true;
            let response = config
                .transport
                .execute(
                    endpoint,
                    outgoing,
                    Limits {
                        max_request_bytes: route.max_request_bytes,
                        max_response_bytes: route.max_response_bytes.min(64 * 1024),
                        total_timeout: deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(2)),
                        ..Limits::default()
                    },
                    child.operation.cancelled.clone(),
                )
                .await?;
            child.record_view(
                Direction::Inbound,
                View::Upstream,
                Data::ResponseStart {
                    status: response.status().as_u16(),
                    headers: super::super::observation::headers(response.headers()),
                },
            )?;
            aap_mcp_upstream::validate_control_ack(response.status(), response.headers())?;
            let mut body = response.into_body();
            while let Some(frame) = body.frame().await {
                let frame = frame?;
                if frame.data_ref().is_none_or(|bytes| !bytes.is_empty()) {
                    return Err(ErrorCode::InspectionUnavailable.into());
                }
            }
            binding.revalidate().await?;
            binding.check()?;
            child.record(
                Direction::Inbound,
                Data::ResponseStart {
                    status: 202,
                    headers: vec![],
                },
            )?;
            child
                .operation
                .transition(OperationState::Dispatching, Some(202))?;
            child.complete()
        };
        let parent_cancelled = async {
            if kind == Kind::Ping {
                parent.cancelled.cancelled().await;
            } else {
                // A cancellation child exists because its parent was cancelled.
                std::future::pending::<()>().await;
            }
        };
        let result = tokio::select! {
            biased;
            _ = self.core.cancelled.cancelled() => Err(ErrorCode::SessionInvalid.into()),
            _ = parent_cancelled => Err(ErrorCode::RequestConflict.into()),
            _ = child_cancelled.cancelled() => Err(ErrorCode::RequestConflict.into()),
            _ = binding.cancelled.cancelled() => Err(ErrorCode::SessionInvalid.into()),
            result = tokio::time::timeout_at(deadline.min(Instant::now() + Duration::from_secs(2)), attempt) =>
                result.unwrap_or_else(|_| Err(ErrorCode::OutcomeUnknown.into())),
        };
        if let Err(error) = &result {
            if child.dispatched {
                binding.invalidate();
            }
            child.fail(error.code);
        }
        result
    }
}
