//! Local cancellation never waits for remote permission or backing-store access.
use super::{
    control::{Control, Kind, SAFE_CANCEL},
    *,
};

impl Session {
    fn current_remote(&self, resource: &str) -> Result<Option<Arc<Binding>>> {
        Ok(self
            .core
            .remote
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .contexts
            .iter()
            .rev()
            .find(|(name, _)| name == resource)
            .map(|(_, binding)| binding.clone()))
    }

    pub(super) async fn cancel_remote_message(
        &self,
        guard: &mut Guard,
        profile: &ResourceProfile,
        target: &Target,
        message: Request,
        deadline: Instant,
    ) -> Result<Response> {
        let cancellation = if let Some(binding) = self.current_remote(&profile.id)? {
            let target = {
                let mut state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
                let target = state.cancel_request(message, Instant::now().into_std())?;
                if matches!(
                    state.state(Instant::now().into_std()),
                    State::Invalid | State::Closed
                ) {
                    binding.cancelled.cancel();
                }
                target
            };
            target.map(|target| (binding, target))
        } else {
            None
        };
        if let Some((binding, cancellation)) = cancellation {
            let operation = self.operation(&cancellation.operation)?;
            let dispatched = operation.status()?.state == OperationState::Dispatching;
            operation.cancel();
            if dispatched {
                // Best effort only. Local work is already stopped; a refused
                // child cannot change that or turn uncertainty into rollback.
                if let Err(error) = self
                    .dispatch_remote_control(
                        &operation,
                        profile,
                        target,
                        Control {
                            binding,
                            outgoing: cancellation.outgoing,
                            kind: Kind::Cancel,
                        },
                        deadline,
                    )
                    .await
                {
                    guard.record_both(
                        Direction::Outbound,
                        Data::PolicyDecision {
                            decision: Decision::Deny,
                            reason: Some(error.code),
                        },
                    )?;
                }
            }
        }
        guard.content(Direction::Outbound, View::Agent, SAFE_CANCEL)?;
        guard.record(
            Direction::Inbound,
            Data::ResponseStart {
                status: 202,
                headers: vec![],
            },
        )?;
        guard.complete_local(202)?;
        empty_response(202)
    }

    fn prepare_operation_cancel(&self, operation: &Operation) -> Result<Option<Control>> {
        if terminal(operation.status()?.state) {
            return Ok(None);
        }
        let Some(binding) = self.current_remote(&operation.request.resource)? else {
            return Ok(None);
        };
        let cancellation = {
            let mut state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
            let cancellation =
                state.cancel_operation(&operation.request.request_id, Instant::now().into_std())?;
            if matches!(
                state.state(Instant::now().into_std()),
                State::Invalid | State::Closed
            ) {
                binding.cancelled.cancel();
            }
            cancellation
        };
        Ok(cancellation.map(|cancellation| Control {
            binding,
            outgoing: cancellation.outgoing,
            kind: Kind::Cancel,
        }))
    }

    pub(crate) async fn cancel_remote_operation(&self, operation: &Operation) {
        // No await until the original operation is cancelled. Preparation only
        // consults bounded in-memory protocol ownership, never store metadata.
        let control = self.prepare_operation_cancel(operation);
        let dispatched = operation
            .status()
            .is_ok_and(|status| status.state == OperationState::Dispatching);
        operation.cancel();
        if !dispatched {
            return;
        }
        let Ok(Some(control)) = control else {
            return;
        };
        let config = &self.core.host.configuration;
        let Some(profile) = config
            .profiles
            .iter()
            .find(|profile| profile.id == operation.request.resource)
        else {
            return;
        };
        let Ok(target) = Target::parse(&operation.request.target) else {
            return;
        };
        let deadline = self.core.expires.min(control.binding.expires);
        let _ = self
            .dispatch_remote_control(operation, profile, &target, control, deadline)
            .await;
    }
}
