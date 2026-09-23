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
    pub relay: Option<relay::ActiveRelay>,
    pub deadline: Option<Instant>,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}
impl State {
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.relay
            .as_ref()
            .map(|relay| relay.io.deadline())
            .or(self.deadline)
    }
}

pub(crate) struct Operation {
    pub request: Arc<stream::Open>,
    pub profile: TcpProfile,
    pub required: bool,
    pub flow: Flow,
    pub cancelled: Cancellation,
    pub(super) changed: tokio::sync::Notify,
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

    pub(super) fn commit_dispatch(&self, session: &Session) -> Result<()> {
        #[cfg(test)]
        session.before_dispatch(&self.request.request_id);
        let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        session.commit_authority(|| {
            if state.status.state != OperationState::Ready || self.cancelled.is_cancelled() {
                return Err(ErrorCode::RequestConflict.into());
            }
            state.status.state = OperationState::Dispatching;
            Ok(())
        })
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
        self.finish_locked(&mut state, cause);
    }

    pub(super) fn finish_locked(&self, state: &mut State, mut cause: stream::Cause) {
        if terminal(state.status.state) {
            return;
        }
        // Wake the driver before dropping the relay's cancellation waiter.
        // Closing an arbitrary adapter need not generate another I/O wakeup.
        self.cancelled.cancel();
        if let Some(mut relay) = state.relay.take() {
            let outcome = relay.io.terminate(cause);
            state.sent_bytes = outcome.sent_bytes;
            state.received_bytes = outcome.received_bytes;
            if cause == stream::Cause::OrderlyEnd && outcome.cause != stream::Cause::OrderlyEnd {
                cause = stream::Cause::InternalError;
            }
            if relay
                .observation
                .finish(
                    cause == stream::Cause::OrderlyEnd,
                    cause,
                    state.sent_bytes,
                    state.received_bytes,
                )
                .is_err()
                && cause == stream::Cause::OrderlyEnd
            {
                cause = stream::Cause::ObservationUnavailable;
            }
        } else {
            if cause == stream::Cause::OrderlyEnd {
                cause = stream::Cause::InternalError;
            }
            if state.flow_started {
                let _ = self.record_locked(Data::FlowClose {
                    complete: false,
                    outbound_bytes: state.sent_bytes,
                    inbound_bytes: state.received_bytes,
                    reason: Some(reason(cause)),
                });
            }
        }
        state.socket.take();
        state.capacity.take();
        state.attachments.take();
        state.deadline = None;
        state.status.state = if cause == stream::Cause::OrderlyEnd {
            OperationState::Completed
        } else if state.status.state == OperationState::Dispatching {
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
    }

    pub(super) fn outcome(&self) -> stream::Terminal {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::outcome_locked(&state)
    }

    pub(super) fn outcome_locked(state: &State) -> stream::Terminal {
        stream::Terminal {
            operation: state.status.clone(),
            cause: state.cause.unwrap_or(stream::Cause::InternalError),
            sent_bytes: state.sent_bytes,
            received_bytes: state.received_bytes,
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

pub(super) fn reason(cause: stream::Cause) -> ErrorCode {
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
    fn fixture() -> (Operation, Recorder) {
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
            changed: tokio::sync::Notify::new(),
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
                relay: None,
                deadline: None,
                sent_bytes: 0,
                received_bytes: 0,
            }),
        };
        (operation, recorder)
    }
    #[test]
    fn cancellation_is_the_last_flow_record() {
        let (operation, recorder) = fixture();
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

    struct SilentIo;
    impl tokio::io::AsyncRead for SilentIo {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _bytes: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }
    impl tokio::io::AsyncWrite for SilentIo {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }
    struct Wakes(AtomicUsize);
    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn terminal_commit_wakes_the_owner_before_dropping_io_state() {
        let (operation, _recorder) = fixture();
        operation.begin_flow().unwrap();
        let mut state = operation.state.lock().unwrap();
        state.status.state = OperationState::Dispatching;
        state.relay = Some(relay::ActiveRelay {
            io: aap_transport::tcp::relay::Duplex::new(
                Box::new(SilentIo),
                Box::new(SilentIo),
                aap_transport::tcp::relay::Limits {
                    max_chunk: 1,
                    send_limit: 1,
                    receive_limit: 1,
                    idle_timeout: Duration::from_secs(1),
                    idle_deadline: Instant::now() + Duration::from_secs(1),
                    lifetime: Instant::now() + Duration::from_secs(2),
                },
                operation.cancelled.clone(),
            )
            .unwrap(),
            observation: observation::Observation::new(
                operation.flow.clone(),
                stream::Inspection::Opaque,
            ),
        });
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wakes.clone());
        let mut cx = std::task::Context::from_waker(&waker);
        let relay = state.relay.as_mut().unwrap();
        assert!(relay.io.poll(&mut cx, &mut relay.observation).is_pending());
        let before = wakes.0.load(Ordering::SeqCst);
        // A watchdog can commit termination without polling the relay again.
        operation.finish_locked(&mut state, stream::Cause::Timeout);
        assert!(
            wakes.0.load(Ordering::SeqCst) > before,
            "terminal commit discarded the owner's cancellation waker"
        );
    }
}
