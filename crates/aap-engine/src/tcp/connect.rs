use super::*;
use state::cause;

impl PendingTcp {
    /// Approval and connection run only while this future is owned. A pending
    /// attachment holds no active socket slot, relay payload, or resolved secret.
    pub async fn connect(mut self) -> std::result::Result<ConnectedTcp, stream::Terminal> {
        let result = tokio::select! {
            biased;
            _ = self.session.core.cancelled.cancelled() => Err(stream::Cause::SessionEnded),
            _ = self.operation.cancelled.cancelled() => Err(stream::Cause::Cancelled),
            _ = tokio::time::sleep_until(self.session.core.expires) => Err(stream::Cause::Timeout),
            result = self.prepare() => result,
        };
        let (socket, capacity, details, timing) = match result {
            Ok(value) => value,
            Err(cause) => {
                self.operation.finish(cause);
                return Err(self.operation.outcome());
            }
        };
        // Recheck after the await while serializing against cancellation.
        let mut state = self
            .operation
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rejected = if Instant::now() >= timing.idle {
            Some(stream::Cause::Timeout)
        } else if self.session.check().is_err() {
            Some(stream::Cause::SessionEnded)
        } else if self.operation.cancelled.is_cancelled() || terminal(state.status.state) {
            Some(stream::Cause::Cancelled)
        } else {
            None
        };
        if let Some(cause) = rejected {
            drop(state);
            drop(socket);
            drop(capacity);
            self.operation.finish(cause);
            return Err(self.operation.outcome());
        }
        state.socket = Some(socket);
        state.capacity = Some(capacity);
        state.deadline = Some(timing.idle);
        state.attachments.take();
        drop(state);
        self.transferred = true;
        let operation = self.operation.clone();
        let cancelled = self.session.core.cancelled.clone();
        let watchdog = tokio::spawn(async move { operation.watch(cancelled).await });
        Ok(ConnectedTcp {
            session: self.session.clone(),
            operation: self.operation.clone(),
            details,
            timing,
            watchdog,
        })
    }

    async fn prepare(
        &self,
    ) -> std::result::Result<(TcpSocket, Capacity, stream::Opened, ConnectionTiming), stream::Cause>
    {
        self.session.check().map_err(cause)?;
        self.operation.begin_flow().map_err(cause)?;
        self.approve().await?;
        let deadline = self
            .session
            .core
            .expires
            .min(Instant::now() + Duration::from_secs(10));
        tokio::time::timeout_at(deadline, self.dial(deadline))
            .await
            .map_err(|_| stream::Cause::Timeout)?
    }

    async fn approve(&self) -> std::result::Result<(), stream::Cause> {
        let config = &self.session.core.host.configuration;
        if !(config.require_approval
            || self.session.core.options.require_approval
            || self.operation.profile.require_approval)
        {
            return Ok(());
        }
        let provider = config
            .approval
            .as_ref()
            .ok_or(stream::Cause::InteractionUnavailable)?;
        let bytes =
            2048 + self.operation.profile.endpoint.len() + self.operation.request.resource.len();
        let _reservation = self.session.reserve_approval(bytes).map_err(cause)?;
        let expires = self
            .session
            .core
            .expires
            .min(Instant::now() + Duration::from_secs(300));
        let request = Arc::new(ConnectionApproval {
            daemon_epoch: self.session.core.host.epoch.clone(),
            session_id: self.session.id().into(),
            approval_id: aap_types::ids::random_id(32).map_err(|_| stream::Cause::InternalError)?,
            configuration_revision: config.catalog.configuration_revision,
            operation: self.operation.request.clone(),
            endpoint: self.operation.profile.endpoint.clone(),
            limits: self.operation.profile.limits,
            inspection: self.operation.profile.inspection,
            require_observation: self.operation.required,
            expires_at: expires.into_std(),
        });
        self.operation
            .transition(OperationState::PendingApproval)
            .map_err(cause)?;
        self.operation
            .record(Data::PolicyDecision {
                decision: Decision::Pending,
                reason: None,
            })
            .map_err(cause)?;
        let approved = tokio::time::timeout_at(
            expires,
            provider.approve_connection(request, self.operation.cancelled.clone()),
        )
        .await
        .map_err(|_| stream::Cause::ApprovalTimeout)?;
        // A ready inner future may beat timeout_at's timer in the same poll.
        // Its result does not extend the immutable approval deadline.
        if Instant::now() >= expires {
            return Err(stream::Cause::ApprovalTimeout);
        }
        if !approved.map_err(cause)? {
            return Err(stream::Cause::ApprovalDenied);
        }
        Ok(())
    }

    async fn dial(
        &self,
        deadline: Instant,
    ) -> std::result::Result<(TcpSocket, Capacity, stream::Opened, ConnectionTiming), stream::Cause>
    {
        self.check_preparation(deadline)?;
        let operation = &self.operation;
        let profile = &operation.profile;
        let config = &self.session.core.host.configuration;
        let authority =
            aap_types::proxy::ConnectAuthority::parse(&profile.endpoint).map_err(cause)?;
        let addresses = config
            .resolver
            .resolve(authority.host(), authority.port())
            .await;
        self.check_preparation(deadline)?;
        let address = profile
            .admit_addresses(&addresses.map_err(cause)?)
            .map_err(cause)?;
        let endpoint = TcpEndpoint::new(&profile.endpoint, address).map_err(cause)?;
        let capacity = Capacity {
            _shared: self
                .session
                .core
                .active
                .clone()
                .try_acquire_owned()
                .map_err(|_| stream::Cause::CapacityExhausted)?,
            _global: self
                .session
                .core
                .host
                .tcp_active
                .clone()
                .try_acquire_owned()
                .map_err(|_| stream::Cause::CapacityExhausted)?,
            _resource: self
                .session
                .core
                .tcp_resources
                .get(&profile.id)
                .ok_or(stream::Cause::PolicyChanged)?
                .clone()
                .try_acquire_owned()
                .map_err(|_| stream::Cause::CapacityExhausted)?,
            _payload: self
                .session
                .core
                .host
                .tcp_payload
                .clone()
                .try_acquire_many_owned(128 * 1024)
                .map_err(|_| stream::Cause::CapacityExhausted)?,
        };
        self.check_preparation(deadline)?;
        operation.transition(OperationState::Ready).map_err(cause)?;
        operation
            .record(Data::PolicyDecision {
                decision: Decision::Allow,
                reason: None,
            })
            .map_err(cause)?;
        operation
            .record(Data::ConnectAdmission {
                authority: profile.endpoint.clone(),
            })
            .map_err(cause)?;
        self.check_preparation(deadline)?;
        operation.commit_dispatch(&self.session).map_err(cause)?;
        let socket = config
            .tcp_connector
            .connect(endpoint, deadline, operation.cancelled.clone())
            .await;
        self.check_preparation(deadline)?;
        let socket = socket.map_err(cause)?;
        let now = Instant::now();
        let lifetime = self
            .session
            .core
            .expires
            .min(now + Duration::from_millis(profile.limits.lifetime_ms));
        let details = stream::Opened {
            request_id: operation.request.request_id.clone(),
            resource: profile.id.clone(),
            max_data_bytes: profile.limits.max_data_bytes,
            send_limit: profile.limits.send_limit,
            receive_limit: profile.limits.receive_limit,
            idle_timeout_ms: profile.limits.idle_timeout_ms,
            remaining_lifetime_ms: lifetime.saturating_duration_since(now).as_millis() as u64,
            inspection: profile.inspection,
            observation: if operation.required {
                stream::Observation::Required
            } else {
                stream::Observation::BestEffort
            },
        };
        details.validate().map_err(cause)?;
        // Until the relay takes ownership, no application progress refreshes idle.
        let idle = lifetime.min(now + Duration::from_millis(profile.limits.idle_timeout_ms));
        Ok((
            socket,
            capacity,
            details,
            ConnectionTiming { lifetime, idle },
        ))
    }

    fn check_preparation(&self, deadline: Instant) -> std::result::Result<(), stream::Cause> {
        if Instant::now() >= deadline {
            return Err(stream::Cause::Timeout);
        }
        self.session.check().map_err(cause)?;
        if self.operation.cancelled.is_cancelled() {
            return Err(stream::Cause::Cancelled);
        }
        Ok(())
    }
}
