use super::*;

pub(super) struct Attachment {
    subscription: Arc<aap_observe::Subscription>,
    scope: aap_observe::Scope,
    expires: Instant,
    shutdown: Cancellation,
    task: tokio::task::JoinHandle<Result<()>>,
    _binding: SocketBinding,
}
impl Attachment {
    pub(super) fn close_admission(&self) {
        self.subscription.close_admission();
    }
    pub(super) fn cancel_listener(&self) {
        self.shutdown.cancel();
    }
    pub(super) async fn join(&mut self) -> bool {
        !matches!((&mut self.task).await, Ok(Ok(())))
    }
    pub(super) fn valid(&self, sessions: &HashMap<String, super::Attachment>) -> bool {
        self.expires > Instant::now()
            && !self.task.is_finished()
            && self
                .scope
                .sessions
                .iter()
                .all(|id| sessions.contains_key(id))
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        self.subscription.close();
        self.shutdown.cancel();
        self.task.abort();
    }
}
impl Control {
    pub(super) fn create_observation(
        &self,
        request: CreateObservation,
    ) -> Result<ObservationAttachment> {
        if !(1..=3600).contains(&request.lifetime_seconds)
            || request.scope.sessions.is_empty()
            || request.scope.sessions.len() > 64
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        Self::prune(&mut state);
        let mut expires = Instant::now() + Duration::from_secs(request.lifetime_seconds);
        for id in &request.scope.sessions {
            let session = state.sessions.get(id).ok_or(ErrorCode::SessionInvalid)?;
            expires = expires.min(session.expires);
        }
        let subscription = Arc::new(
            self.recorder
                .subscribe(request.scope.clone(), request.limits)?,
        );
        let id = subscription.id().to_owned();
        let name = format!("o-{id}.sock");
        let binding = self
            .runtime
            .bind_socket(&name)
            .map_err(|_| ErrorCode::InternalError)?;
        let listener = binding.listener().map_err(|_| ErrorCode::InternalError)?;
        let shutdown = Cancellation::default();
        let cancelled = shutdown.clone();
        let handler = Arc::new(Scoped {
            subscription: subscription.clone(),
            expires,
        });
        let retained = subscription.clone();
        let task = tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                _=tokio::time::sleep_until(expires.into())=>Ok(()),
                result=aap_http::serve_local(listener,handler,rustix::process::geteuid().as_raw(),cancelled)=>result,
            };
            retained.close();
            result
        });
        state.observers.insert(
            id.clone(),
            Attachment {
                subscription,
                scope: request.scope,
                expires,
                shutdown,
                task,
                _binding: binding,
            },
        );
        Ok(ObservationAttachment {
            subscription_id: id,
            observation_socket: name,
        })
    }
    pub(super) fn revoke_observation(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        let attachment = state
            .observers
            .remove(id)
            .ok_or(ErrorCode::ObservationUnavailable)?;
        drop(attachment);
        Ok(())
    }
}
struct Scoped {
    subscription: Arc<aap_observe::Subscription>,
    expires: Instant,
}
impl LocalHandler for Scoped {
    fn handle(&self, request: http::Request<Incoming>) -> BoxFuture<'_, Response> {
        Box::pin(async move { self.dispatch(request).await.unwrap_or_else(error_response) })
    }
}
impl Scoped {
    async fn dispatch(&self, request: http::Request<Incoming>) -> Result<Response> {
        validate_local_request(&request)?;
        let path = request.uri().path().to_owned();
        if !["/aap/observe/v1/read", "/aap/observe/v1/ack"].contains(&path.as_str()) {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let body = read_body(request).await?;
        if self.expires <= Instant::now() {
            self.subscription.close();
            return Err(ErrorCode::ObservationUnavailable.into());
        }
        match path.as_str() {
            "/aap/observe/v1/read" => {
                let request: ReadSubscription = decode(&body)?;
                json_response(&self.subscription.read(
                    request.cursor.as_ref(),
                    request.limit,
                    1024 * 1024,
                )?)
            }
            "/aap/observe/v1/ack" => {
                let cursor: aap_observe::SubscriptionCursor = decode(&body)?;
                self.subscription.acknowledge(&cursor)?;
                json_response(&serde_json::json!({"acknowledged":true}))
            }
            _ => Err(ErrorCode::PolicyDenied.into()),
        }
    }
}
