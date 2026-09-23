//! Bounded host handoffs, not an agent API or a signed approval protocol.
use aap_engine::{ApprovalProvider, ApprovalRequest};
use aap_observe::{Subscription, SubscriptionBatch, SubscriptionCursor};
use aap_transport::Cancellation;
use aap_types::{BoxFuture, ErrorCode, Result};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

pub struct ApprovalInbox {
    sender: mpsc::Sender<PendingApproval>,
}
pub struct PendingApproval {
    request: Arc<ApprovalRequest>,
    decision: oneshot::Sender<bool>,
}
impl PendingApproval {
    pub fn request(&self) -> &ApprovalRequest {
        &self.request
    }

    pub fn decide(self, allow: bool) -> Result<()> {
        self.decision
            .send(allow)
            .map_err(|_| ErrorCode::RequestConflict.into())
    }
}
impl ApprovalInbox {
    pub fn new(capacity: usize) -> Result<(Self, mpsc::Receiver<PendingApproval>)> {
        if !(1..=16).contains(&capacity) {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let (sender, receiver) = mpsc::channel(capacity);
        Ok((Self { sender }, receiver))
    }
}
impl ApprovalProvider for ApprovalInbox {
    fn approve(
        &self,
        request: Arc<ApprovalRequest>,
        cancel: Cancellation,
    ) -> BoxFuture<'_, Result<bool>> {
        Box::pin(async move {
            if cancel.is_cancelled() {
                return Err(ErrorCode::RequestConflict.into());
            }
            let deadline = tokio::time::Instant::from_std(request.expires_at);
            if deadline <= tokio::time::Instant::now() {
                return Err(ErrorCode::InteractionUnavailable.into());
            }
            let (decision, received) = oneshot::channel();
            self.sender
                .try_send(PendingApproval { request, decision })
                .map_err(|_| ErrorCode::InteractionUnavailable)?;
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(ErrorCode::RequestConflict.into()),
                _ = tokio::time::sleep_until(deadline) => Err(ErrorCode::InteractionUnavailable.into()),
                result = received => result.map_err(|_| ErrorCode::InteractionUnavailable.into()),
            }
        })
    }
}

pub struct ObservationPage {
    pub batch: SubscriptionBatch,
    consumed: oneshot::Sender<()>,
}
impl ObservationPage {
    pub fn acknowledge(self) -> Result<()> {
        self.consumed
            .send(())
            .map_err(|_| ErrorCode::RequestConflict.into())
    }
}
pub struct ObservationForwarder {
    subscription: Subscription,
    cursor: Option<SubscriptionCursor>,
}
impl ObservationForwarder {
    pub fn new(subscription: Subscription) -> Self {
        Self {
            subscription,
            cursor: None,
        }
    }
    /// One bounded page, acknowledged only after the consumer confirms receipt.
    pub async fn forward(&mut self, destination: &mpsc::Sender<ObservationPage>) -> Result<usize> {
        if destination.max_capacity() > 16 {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let batch = self
            .subscription
            .read(self.cursor.as_ref(), 32, 16 * 1024)?;
        let count = batch.deliveries.len();
        if count == 0 && batch.gap.is_none() {
            return Ok(0);
        }
        let cursor = batch.cursor.clone();
        let (consumed, receipt) = oneshot::channel();
        destination
            .try_send(ObservationPage { batch, consumed })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ErrorCode::LimitExceeded,
                mpsc::error::TrySendError::Closed(_) => ErrorCode::ObservationUnavailable,
            })?;
        tokio::select! {
            biased;
            _ = tokio::time::sleep(Duration::from_secs(10)) => Err(ErrorCode::ObservationUnavailable),
            result = receipt => result.map_err(|_| ErrorCode::ObservationUnavailable),
        }?;
        self.subscription.acknowledge(&cursor)?;
        self.cursor = Some(cursor);
        Ok(count)
    }
}
impl Drop for ObservationForwarder {
    fn drop(&mut self) {
        self.subscription.close();
    }
}
