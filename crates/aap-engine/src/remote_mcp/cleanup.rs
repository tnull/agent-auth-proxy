//! Local closure is final; the separately admitted remote attempt is best effort.
use super::{
    control::{Control, Kind},
    *,
};
use aap_types::mcp::{CLEANUP_HEADER, CleanupOutcome};

struct Closing(Arc<Binding>);
impl Drop for Closing {
    fn drop(&mut self) {
        self.0.closing.store(false, Ordering::Release);
    }
}

impl Session {
    fn prepare_remote_close(
        &self,
        resource: &str,
        deadline: Instant,
    ) -> Result<Option<(Closing, aap_mcp_upstream::Outgoing, Instant)>> {
        // Serialize selection/closure with fresh generation creation. Merely
        // cloning the current binding first would leave a reinitialize race.
        let vault = self
            .core
            .remote
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        let Some((_, binding)) = vault
            .contexts
            .iter()
            .rev()
            .find(|(name, _)| name == resource)
        else {
            return Ok(None);
        };
        let mut state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
        let now = Instant::now();
        let deadline =
            deadline
                .min(binding.expires)
                .min(if state.state(now.into_std()) == State::Ready {
                    binding.expires
                } else {
                    binding.handshake
                });
        let headers = state.close(now.into_std());
        binding.cancelled.cancel();
        if headers.is_empty() {
            return Ok(None);
        }
        binding.closing.store(true, Ordering::Release);
        Ok(Some((
            Closing(binding.clone()),
            aap_mcp_upstream::Outgoing {
                headers,
                body: vec![],
            },
            deadline,
        )))
    }

    pub(super) async fn close_remote_context(
        &self,
        guard: &mut Guard,
        profile: &ResourceProfile,
        target: &Target,
        item_id: &str,
        deadline: Instant,
    ) -> Result<Response> {
        let item = self
            .core
            .host
            .configuration
            .catalog
            .items
            .iter()
            .find(|item| item.item_id == item_id)
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
                method: "DELETE".into(),
                target: target.as_str().into(),
                headers: super::super::observation::request_headers(
                    &guard.operation.request.headers,
                ),
            },
        )?;
        // Closure precedes any store interaction, DNS, capacity wait, or remote
        // dispatch. The RAII owner releases only the reinitialization barrier.
        let outcome = if let Some((closing, outgoing, deadline)) =
            self.prepare_remote_close(&profile.id, deadline)?
        {
            self.dispatch_remote_control(
                &guard.operation,
                profile,
                target,
                Control {
                    binding: closing.0.clone(),
                    outgoing,
                    kind: Kind::Delete,
                },
                deadline,
            )
            .await
            .unwrap_or(CleanupOutcome::Skipped)
        } else {
            CleanupOutcome::Skipped
        };
        guard.record(
            Direction::Inbound,
            Data::ResponseStart {
                status: 204,
                headers: vec![(CLEANUP_HEADER.into(), outcome.as_str().into())],
            },
        )?;
        guard.complete_local(204)?;
        let mut response = empty_response(204)?;
        response.headers_mut().insert(
            CLEANUP_HEADER,
            http::HeaderValue::from_static(outcome.as_str()),
        );
        Ok(response)
    }
}
