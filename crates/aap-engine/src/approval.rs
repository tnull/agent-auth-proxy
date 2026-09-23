use super::{pipeline::Guard, *};
use aap_observe::{Data, Decision, Direction};
use aap_secrets::Lease;

pub(super) struct ApprovalReservation {
    _pending: OwnedSemaphorePermit,
    session: Arc<SessionCore>,
    bytes: usize,
}
impl Drop for ApprovalReservation {
    fn drop(&mut self) {
        self.session
            .pending_bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
impl Session {
    pub(super) fn reserve_approval(&self, bytes: usize) -> Result<ApprovalReservation> {
        let pending = self
            .core
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::LimitExceeded)?;
        self.core
            .pending_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= 4 * 1024 * 1024)
            })
            .map_err(|_| ErrorCode::LimitExceeded)?;
        Ok(ApprovalReservation {
            _pending: pending,
            session: self.core.clone(),
            bytes,
        })
    }
    pub(super) async fn approve_operation(
        &self,
        guard: &Guard,
        item_id: &str,
        lease: &Lease,
        context_id: Option<&str>,
        deadline: Instant,
    ) -> Result<()> {
        let config = &self.core.host.configuration;
        let provider = config
            .approval
            .as_ref()
            .ok_or(ErrorCode::InteractionUnavailable)?;
        let input = &guard.operation.request;
        let bytes = input.body_base64.len()
            + input.target.len()
            + 1024
            + input
                .headers
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>();
        let _reservation = self.reserve_approval(bytes)?;
        let expires = deadline.min(Instant::now() + Duration::from_secs(300));
        let request = Arc::new(ApprovalRequest {
            daemon_epoch: self.core.host.epoch.clone(),
            session_id: self.id().into(),
            approval_id: aap_types::ids::random_id(32).map_err(|_| ErrorCode::InternalError)?,
            configuration_revision: config.catalog.configuration_revision,
            item_id: item_id.into(),
            operation: input.clone(),
            credential_lease: lease.clone(),
            context_id: context_id.map(str::to_owned),
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
        if !tokio::time::timeout_at(
            expires,
            provider.approve(request, guard.operation.cancelled.clone()),
        )
        .await
        .map_err(|_| ErrorCode::InteractionUnavailable)??
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        Ok(())
    }
}
