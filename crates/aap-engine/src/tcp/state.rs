use super::*;

pub(super) struct AttachmentSlots {
    pub _session: OwnedSemaphorePermit,
    pub _host: OwnedSemaphorePermit,
}

pub(super) struct Capacity {
    pub _shared: OwnedSemaphorePermit,
    pub _global: OwnedSemaphorePermit,
    pub _resource: OwnedSemaphorePermit,
    pub _payload: OwnedSemaphorePermit,
}

pub(super) struct State {
    pub status: OperationStatus,
    pub cause: Option<stream::Cause>,
    pub flow_started: bool,
    pub socket: Option<TcpSocket>,
    pub capacity: Option<Capacity>,
    pub attachments: Option<AttachmentSlots>,
}

pub(crate) struct Operation {
    pub request: Arc<stream::Open>,
    pub profile: TcpProfile,
    pub required: bool,
    pub flow: Flow,
    pub cancelled: Cancellation,
    pub(super) state: Mutex<State>,
}

impl Operation {
    pub fn status(&self) -> Result<OperationStatus> {
        Ok(self
            .state
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .status
            .clone())
    }

    pub(super) fn transition(&self, next: OperationState) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        if terminal(state.status.state) || self.cancelled.is_cancelled() {
            return Err(ErrorCode::RequestConflict.into());
        }
        state.status.state = next;
        Ok(())
    }

    pub(super) fn begin_flow(&self) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        if terminal(state.status.state) || self.cancelled.is_cancelled() {
            return Err(ErrorCode::RequestConflict.into());
        }
        self.record_locked(Data::FlowOpen {})?;
        state.flow_started = true;
        Ok(())
    }

    pub(super) fn record(&self, data: Data) -> Result<()> {
        let state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        if terminal(state.status.state) || self.cancelled.is_cancelled() {
            return Err(ErrorCode::RequestConflict.into());
        }
        self.record_locked(data)
    }

    fn record_locked(&self, data: Data) -> Result<()> {
        self.flow.record_batch(
            [View::Agent, View::Upstream]
                .into_iter()
                .map(|view| Emission {
                    direction: Direction::Outbound,
                    view,
                    inspection: Inspection::MetadataOnly,
                    redaction: Redaction::Complete,
                    data: data.clone(),
                })
                .collect(),
        )
    }

    /// Terminal state, socket closure, and release of connected capacity are one
    /// critical section. A later cancellation/drop cannot overwrite its outcome.
    pub fn finish(&self, cause: stream::Cause) {
        self.cancelled.cancel();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if terminal(state.status.state) {
            return;
        }
        state.socket.take();
        state.capacity.take();
        state.attachments.take();
        state.status.state = if state.status.state == OperationState::Dispatching {
            OperationState::OutcomeUnknown
        } else {
            match cause {
                stream::Cause::Cancelled
                | stream::Cause::SessionEnded
                | stream::Cause::AttachmentLost => OperationState::Cancelled,
                stream::Cause::ApprovalDenied | stream::Cause::PolicyChanged => {
                    OperationState::Denied
                }
                stream::Cause::ApprovalTimeout | stream::Cause::Timeout => OperationState::Expired,
                _ => OperationState::Failed,
            }
        };
        state.cause = Some(cause);
        if state.flow_started {
            let _ = self.record_locked(Data::FlowClose {
                complete: false,
                outbound_bytes: 0,
                inbound_bytes: 0,
                reason: Some(reason(cause)),
            });
        }
    }

    pub(super) fn outcome(&self) -> stream::Terminal {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stream::Terminal {
            operation: state.status.clone(),
            cause: state.cause.unwrap_or(stream::Cause::InternalError),
            sent_bytes: 0,
            received_bytes: 0,
        }
    }
}

pub(super) fn cause(error: Error) -> stream::Cause {
    match error.code {
        ErrorCode::SessionInvalid => stream::Cause::SessionEnded,
        ErrorCode::RequestConflict => stream::Cause::Cancelled,
        ErrorCode::PolicyDenied => stream::Cause::PolicyChanged,
        ErrorCode::LimitExceeded => stream::Cause::CapacityExhausted,
        ErrorCode::InteractionUnavailable => stream::Cause::InteractionUnavailable,
        ErrorCode::ObservationUnavailable => stream::Cause::ObservationUnavailable,
        ErrorCode::OutcomeUnknown | ErrorCode::UpstreamUnavailable => {
            stream::Cause::UpstreamUnavailable
        }
        _ => stream::Cause::InternalError,
    }
}

fn reason(cause: stream::Cause) -> ErrorCode {
    match cause {
        stream::Cause::ApprovalDenied | stream::Cause::PolicyChanged => ErrorCode::PolicyDenied,
        stream::Cause::ApprovalTimeout | stream::Cause::InteractionUnavailable => {
            ErrorCode::InteractionUnavailable
        }
        stream::Cause::CapacityExhausted
        | stream::Cause::LimitExceeded
        | stream::Cause::Timeout => ErrorCode::LimitExceeded,
        stream::Cause::ObservationUnavailable => ErrorCode::ObservationUnavailable,
        stream::Cause::UpstreamUnavailable => ErrorCode::UpstreamUnavailable,
        stream::Cause::SessionEnded => ErrorCode::SessionInvalid,
        stream::Cause::InvalidFrame => ErrorCode::RequestInvalid,
        stream::Cause::InternalError => ErrorCode::InternalError,
        _ => ErrorCode::OutcomeUnknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_is_the_last_flow_record() {
        let recorder =
            Recorder::new(aap_types::ids::random_id(16).unwrap(), 16, 64 * 1024).unwrap();
        let request = Arc::new(stream::Open {
            request_id: aap_types::ids::random_id(16).unwrap(),
            resource: "raw".into(),
        });
        let operation = Operation {
            request: request.clone(),
            profile: TcpProfile {
                id: "raw".into(),
                endpoint: "raw.test:9000".into(),
                addresses: aap_policy::AddressPolicy::Public,
                limits: TcpLimits::default(),
                inspection: stream::Inspection::Opaque,
                require_approval: false,
                require_observation: true,
            },
            required: true,
            flow: Flow::new(
                recorder.clone(),
                FlowContext {
                    session_id: aap_types::ids::random_id(16).unwrap(),
                    request_id: Some(request.request_id.clone()),
                    parent_request_id: None,
                    policy_version: 1,
                    protocol: Protocol::Tcp,
                },
                true,
            )
            .unwrap(),
            cancelled: Cancellation::default(),
            state: Mutex::new(State {
                status: OperationStatus {
                    request_id: request.request_id.clone(),
                    state: OperationState::Validated,
                    status: None,
                },
                cause: None,
                flow_started: false,
                socket: None,
                capacity: None,
                attachments: None,
            }),
        };
        operation.begin_flow().unwrap();
        operation.finish(stream::Cause::Cancelled);
        assert!(
            operation
                .record(Data::PolicyDecision {
                    decision: Decision::Allow,
                    reason: None
                })
                .is_err(),
            "cancelled flow accepted a late policy record"
        );
        let records = recorder.read(None, 16).unwrap().records;
        assert_eq!(records.len(), 4);
        assert!(matches!(
            records.last().unwrap().event.data,
            Data::FlowClose {
                complete: false,
                ..
            }
        ));
    }
}
