use crate::*;
use aap_config::{PrivateDir, SocketBinding};
use aap_engine::{Broker, Session, SessionOptions};
use aap_http::{LocalHandler, error_response, json_response, read_body, validate_local_request};
use aap_observe::Recorder;
use aap_secrets::{SecretBytes, SecretStore};
use aap_store_sqlite::{OpenMode, SqliteStore};
use aap_transport::{Cancellation, Resolver, SystemResolver};
use aap_types::{BoxFuture, ErrorCode, Response, Result};
use hyper::body::Incoming;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
mod observation;
mod retirement;
#[cfg(test)]
mod tests;

#[cfg(test)]
type ReloadHook = Box<dyn FnOnce() -> Result<()> + Send>;

struct ConfiguredResolver {
    hosts: HashMap<String, Vec<IpAddr>>,
    system: SystemResolver,
}
impl Resolver for ConfiguredResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            match self.hosts.get(host) {
                Some(addresses) => Ok(addresses
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, port))
                    .collect()),
                None => self.system.resolve(host, port).await,
            }
        })
    }
}
fn broker(loaded: &Loaded, store: Arc<SqliteStore>, recorder: Recorder) -> Result<Arc<Broker>> {
    let configuration = &loaded.configuration;
    Ok(Arc::new(Broker::new(aap_engine::Configuration {
        catalog: loaded.catalog.clone(),
        profiles: configuration.profiles.clone(),
        tcp_profiles: configuration.tcp_profiles.clone(),
        stores: HashMap::from([(
            configuration.store.alias.clone(),
            store as Arc<dyn SecretStore>,
        )]),
        resolver: Arc::new(ConfiguredResolver {
            hosts: configuration.static_hosts.clone(),
            system: SystemResolver {
                timeout: Duration::from_secs(10),
            },
        }),
        transport: Arc::new(crate::transport(configuration)?),
        tcp_connector: Arc::new(aap_transport::tcp::SystemTcpConnector),
        inspector: Arc::new(aap_providers::TextOnly),
        approval: None,
        require_approval: configuration.require_approval,
        recorder,
    })?))
}
struct Attachment {
    session: Session,
    _binding: SocketBinding,
    shutdown: Cancellation,
    task: tokio::task::JoinHandle<Result<()>>,
    expires: Instant,
}
impl Drop for Attachment {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}
struct Generation {
    loaded: Loaded,
    broker: Arc<Broker>,
    sessions: HashMap<String, Attachment>,
    observers: HashMap<String, observation::Attachment>,
    interception: Option<Arc<crate::interception::StoreInterception>>,
    last_reload: Option<ReloadOutcome>,
    retirement: Option<retirement::Job>,
}
struct Control {
    daemon_epoch: String,
    directory: Arc<PrivateDir>,
    runtime: Arc<PrivateDir>,
    store: Arc<SqliteStore>,
    recorder: Recorder,
    state: Arc<Mutex<Generation>>,
    reload_gate: tokio::sync::Mutex<()>,
    #[cfg(test)]
    prepared_hook: Mutex<Option<ReloadHook>>,
    #[cfg(test)]
    cleanup_hook: Mutex<Option<ReloadHook>>,
}
impl Control {
    #[cfg(test)]
    fn run_hook(hook: &Mutex<Option<ReloadHook>>) -> Result<()> {
        let callback = hook.lock().unwrap().take();
        match callback {
            Some(callback) => callback(),
            None => Ok(()),
        }
    }
    fn create(&self, request: CreateSession) -> Result<SessionAttachment> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        Self::prune(&mut state);
        let session = state.broker.create_session(SessionOptions {
            resources: request.resources,
            items: request.items,
            lifetime: Duration::from_secs(request.lifetime_seconds),
            require_approval: request.require_approval,
            require_observation: request.require_observation
                || state.loaded.configuration.observation.required,
        })?;
        let id = session.id().to_owned();
        let name = format!("s-{id}.sock");
        let binding = self
            .runtime
            .bind_socket(&name)
            .map_err(|_| ErrorCode::InternalError)?;
        let shutdown = Cancellation::default();
        let listener = binding.listener().map_err(|_| ErrorCode::InternalError)?;
        let identities = state.interception.clone();
        let session_service = Arc::new(session.clone());
        let cancelled = shutdown.clone();
        let task = tokio::spawn(async move {
            let uid = rustix::process::geteuid().as_raw();
            match identities {
                Some(identities) => {
                    aap_http::serve_intercepting_session(
                        listener,
                        session_service,
                        identities,
                        uid,
                        cancelled,
                    )
                    .await
                }
                None => aap_http::serve_session(listener, session_service, uid, cancelled).await,
            }
        });
        state.sessions.insert(
            id.clone(),
            Attachment {
                session,
                _binding: binding,
                shutdown,
                task,
                expires: Instant::now() + Duration::from_secs(request.lifetime_seconds),
            },
        );
        Ok(SessionAttachment {
            session_id: id,
            ingress_socket: name,
        })
    }
    fn revoke(&self, id: &str) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        let attachment = state.sessions.remove(id).ok_or(ErrorCode::SessionInvalid)?;
        state.broker.revoke(&attachment.session)?;
        drop(attachment);
        Self::prune(&mut state);
        Ok(())
    }
    fn prune(state: &mut Generation) {
        let broker = state.broker.clone();
        state.sessions.retain(|_, attachment| {
            if attachment.expires <= Instant::now() || attachment.task.is_finished() {
                let _ = broker.revoke(&attachment.session);
                false
            } else {
                true
            }
        });
        state
            .observers
            .retain(|_, attachment| attachment.valid(&state.sessions));
    }
    fn shutdown(&self) -> Result<()> {
        let (broker, observers, sessions) = {
            let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
            state.broker.close_admission();
            for observer in state.observers.values() {
                observer.close_admission();
            }
            (
                state.broker.clone(),
                std::mem::take(&mut state.observers),
                std::mem::take(&mut state.sessions),
            )
        };
        let closed = broker.close();
        // Wakers and attachment destructors must not run under publication.
        drop((observers, sessions));
        closed
    }
    async fn reload(&self) -> Result<ReloadOutcome> {
        let _exclusive = self
            .reload_gate
            .try_lock()
            .map_err(|_| ErrorCode::LimitExceeded)?;
        let previous = {
            let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
            if state.broker.is_closed() {
                return Err(ErrorCode::SessionInvalid.into());
            }
            if state
                .retirement
                .as_ref()
                .is_some_and(retirement::Job::is_active)
            {
                return Err(ErrorCode::LimitExceeded.into());
            }
            if let Some(job) = &state.retirement {
                state.last_reload = Some(job.outcome());
            }
            state.retirement.take()
        };
        if let Some(previous) = previous {
            let outcome = previous.join().await;
            self.state
                .lock()
                .map_err(|_| ErrorCode::InternalError)?
                .last_reload = Some(outcome);
        }
        let directory = self.directory.clone();
        let loaded = tokio::task::spawn_blocking(move || crate::load(&directory))
            .await
            .map_err(|_| ErrorCode::InternalError)??;
        let candidate = broker(&loaded, self.store.clone(), self.recorder.clone())?;
        let interception = loaded
            .configuration
            .interception
            .as_ref()
            .map(|configuration| {
                crate::interception::StoreInterception::new(configuration, self.store.clone())
            })
            .transpose()?;
        #[cfg(test)]
        Self::run_hook(&self.prepared_hook)?;
        let (waiter, deadline, start) = {
            let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
            if state.broker.is_closed() {
                return Err(ErrorCode::SessionInvalid.into());
            }
            if loaded.configuration.configuration_revision
                <= state.loaded.configuration.configuration_revision
                || loaded.configuration.store != state.loaded.configuration.store
                || loaded.configuration.runtime_directory
                    != state.loaded.configuration.runtime_directory
                || loaded.configuration.observation != state.loaded.configuration.observation
            {
                return Err(ErrorCode::RequestInvalid.into());
            }
            let revision = loaded.configuration.configuration_revision;
            let outcome = ReloadOutcome {
                configuration_revision: revision,
                retirement: RetirementStatus {
                    configuration_revision: state.loaded.configuration.configuration_revision,
                    authority_closed: true,
                    authority_cleanup: AuthorityCleanup::Pending,
                    attachment_tasks_pending: state.sessions.len() + state.observers.len(),
                    attachment_cleanup_failed: false,
                    cleanup_deadline_exceeded: false,
                    drain_confirmed: false,
                },
            };
            // All fallible preparation precedes this commitment. No notification,
            // cleanup callback, or suspension can interleave closure and publication.
            let deadline = Instant::now() + retirement::BUDGET;
            state.broker.close_admission();
            for observer in state.observers.values() {
                observer.close_admission();
            }
            let retired = std::mem::replace(&mut state.broker, candidate);
            let observers = std::mem::take(&mut state.observers);
            let sessions = std::mem::take(&mut state.sessions);
            state.loaded = loaded;
            state.interception = interception;
            state.last_reload = Some(outcome.clone());
            let (job, start) = retirement::Job::start(
                Arc::downgrade(&self.state),
                outcome,
                deadline,
                retired,
                sessions,
                observers,
                #[cfg(test)]
                self.cleanup_hook.lock().unwrap().take(),
            );
            let waiter = job.waiter();
            state.retirement = Some(job);
            (waiter, deadline, start)
        };
        // Transfer work to the retained job before the first suspension point.
        // Dropping this operator future only drops its observation of cleanup.
        let _ = start.send(());
        drop(_exclusive);
        Ok(waiter.wait(deadline).await)
    }
    async fn wait_retirement(&self, deadline: Instant) -> Result<()> {
        let waiter = self
            .state
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .retirement
            .as_ref()
            .map(retirement::Job::waiter);
        if let Some(waiter) = waiter {
            let outcome = waiter.wait(deadline).await;
            if outcome.retirement.authority_cleanup != AuthorityCleanup::Complete
                || outcome.retirement.attachment_tasks_pending != 0
                || outcome.retirement.attachment_cleanup_failed
                || outcome.retirement.cleanup_deadline_exceeded
            {
                return Err(ErrorCode::InternalError.into());
            }
        }
        Ok(())
    }
    async fn dispatch(&self, request: http::Request<Incoming>) -> Result<Response> {
        validate_local_request(&request)?;
        let path = request.uri().path().to_owned();
        if ![
            "/aap/operator/v1/session/create",
            "/aap/operator/v1/session/revoke",
            "/aap/operator/v1/observation/create",
            "/aap/operator/v1/observation/revoke",
            "/aap/operator/v1/status",
            "/aap/operator/v1/reload",
        ]
        .contains(&path.as_str())
        {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let body = read_body(request).await?;
        match path.as_str() {
            "/aap/operator/v1/session/create" => json_response(&self.create(decode(&body)?)?),
            "/aap/operator/v1/observation/create" => {
                json_response(&self.create_observation(decode(&body)?)?)
            }
            "/aap/operator/v1/observation/revoke" => {
                let request: ObservationReference = decode(&body)?;
                self.revoke_observation(&request.subscription_id)?;
                json_response(&serde_json::json!({"revoked":true}))
            }
            "/aap/operator/v1/session/revoke" => {
                let request: SessionReference = decode(&body)?;
                self.revoke(&request.session_id)?;
                json_response(&serde_json::json!({"revoked":true}))
            }
            "/aap/operator/v1/reload" => {
                let _: Empty = decode(&body)?;
                json_response(&self.reload().await?)
            }
            "/aap/operator/v1/status" => {
                let _: Empty = decode(&body)?;
                let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
                Self::prune(&mut state);
                if let Some(job) = &state.retirement {
                    state.last_reload = Some(job.outcome());
                }
                json_response(&serde_json::json!({
                    "daemon_epoch": self.daemon_epoch,
                    "configuration_revision": state.loaded.configuration.configuration_revision,
                    "admission_closed": state.broker.is_closed(),
                    "sessions": state.sessions.len(),
                    "observers": state.observers.len(),
                    "last_reload": state.last_reload,
                }))
            }
            _ => Err(ErrorCode::PolicyDenied.into()),
        }
    }
}
impl LocalHandler for Control {
    fn handle(&self, request: http::Request<Incoming>) -> BoxFuture<'_, Response> {
        Box::pin(async move { self.dispatch(request).await.unwrap_or_else(error_response) })
    }
}
struct Observation(Recorder);
impl LocalHandler for Observation {
    fn handle(&self, request: http::Request<Incoming>) -> BoxFuture<'_, Response> {
        Box::pin(async move { self.dispatch(request).await.unwrap_or_else(error_response) })
    }
}
impl Observation {
    async fn dispatch(&self, request: http::Request<Incoming>) -> Result<Response> {
        validate_local_request(&request)?;
        let path = request.uri().path().to_owned();
        if !["/aap/observe/v1/read", "/aap/observe/v1/ack"].contains(&path.as_str()) {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let body = read_body(request).await?;
        match path.as_str() {
            "/aap/observe/v1/read" => {
                let request: ReadEvents = decode(&body)?;
                json_response(&self.0.read_bounded(
                    request.cursor.as_ref(),
                    request.limit,
                    1024 * 1024,
                )?)
            }
            "/aap/observe/v1/ack" => {
                let cursor: aap_observe::Cursor = decode(&body)?;
                self.0.acknowledge(&cursor)?;
                json_response(&serde_json::json!({"acknowledged":true}))
            }
            _ => Err(ErrorCode::PolicyDenied.into()),
        }
    }
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    aap_types::json::decode(bytes).map_err(|_| ErrorCode::RequestInvalid.into())
}

pub async fn serve(directory: PathBuf, key: SecretBytes) -> Result<()> {
    let directory =
        Arc::new(PrivateDir::open(&directory, false).map_err(|_| ErrorCode::RequestInvalid)?);
    let loaded = {
        let directory = directory.clone();
        tokio::task::spawn_blocking(move || crate::load(&directory))
            .await
            .map_err(|_| ErrorCode::InternalError)??
    };
    let runtime = Arc::new(
        PrivateDir::open(&loaded.configuration.runtime_directory, false)
            .map_err(|_| ErrorCode::RequestInvalid)?,
    );
    let lock = match runtime.open_file("daemon.lock", true) {
        Ok(file) => file,
        Err(aap_config::Error::NotFound) => runtime
            .create_file("daemon.lock")
            .map_err(|_| ErrorCode::InternalError)?,
        Err(_) => return Err(ErrorCode::RequestInvalid.into()),
    };
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| ErrorCode::RequestConflict)?;
    let store = Arc::new(
        SqliteStore::open(
            Arc::new(
                PrivateDir::open(&loaded.configuration.store.directory, false)
                    .map_err(|_| ErrorCode::RequestInvalid)?,
            ),
            key,
            OpenMode::Existing,
            tokio::runtime::Handle::current(),
        )
        .await?,
    );
    let epoch = aap_types::ids::random_id(16).map_err(|_| ErrorCode::InternalError)?;
    let recorder = Recorder::new(
        epoch.clone(),
        loaded.configuration.observation.max_events,
        loaded.configuration.observation.max_bytes,
    )?;
    let broker = broker(&loaded, store.clone(), recorder.clone())?;
    let interception = loaded
        .configuration
        .interception
        .as_ref()
        .map(|configuration| {
            crate::interception::StoreInterception::new(configuration, store.clone())
        })
        .transpose()?;
    let control = Arc::new(Control {
        daemon_epoch: epoch.clone(),
        directory,
        runtime: runtime.clone(),
        store: store.clone(),
        recorder: recorder.clone(),
        state: Arc::new(Mutex::new(Generation {
            loaded,
            broker,
            sessions: HashMap::new(),
            observers: HashMap::new(),
            interception,
            last_reload: None,
            retirement: None,
        })),
        reload_gate: tokio::sync::Mutex::new(()),
        #[cfg(test)]
        prepared_hook: Mutex::new(None),
        #[cfg(test)]
        cleanup_hook: Mutex::new(None),
    });
    let ready = Ready {
        schema_version: 1,
        daemon_epoch: epoch.clone(),
        control_socket: format!("c-{epoch}.sock"),
        observation_socket: format!("o-{epoch}.sock"),
    };
    let control_binding = runtime
        .bind_socket(&ready.control_socket)
        .map_err(|_| ErrorCode::InternalError)?;
    let observation_binding = runtime
        .bind_socket(&ready.observation_socket)
        .map_err(|_| ErrorCode::InternalError)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| ErrorCode::InternalError)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| ErrorCode::InternalError)?;
    let shutdown = Cancellation::default();
    let uid = rustix::process::geteuid().as_raw();
    // JoinSet owns both listeners even if publishing readiness fails. A task
    // consumed by select is never polled a second time during shutdown.
    let mut listeners = tokio::task::JoinSet::new();
    let control_listener = control_binding
        .listener()
        .map_err(|_| ErrorCode::InternalError)?;
    let observation_listener = observation_binding
        .listener()
        .map_err(|_| ErrorCode::InternalError)?;
    let control_handler = control.clone();
    let control_shutdown = shutdown.clone();
    listeners.spawn(async move {
        (
            ErrorCode::InternalError,
            aap_http::serve_local(control_listener, control_handler, uid, control_shutdown).await,
        )
    });
    let observation_shutdown = shutdown.clone();
    listeners.spawn(async move {
        (
            ErrorCode::ObservationUnavailable,
            aap_http::serve_local(
                observation_listener,
                Arc::new(Observation(recorder)),
                uid,
                observation_shutdown,
            )
            .await,
        )
    });
    let readiness = serde_json::to_vec(&ready).map_err(|_| ErrorCode::InternalError)?;
    runtime
        .write_atomic("control.json", &readiness, 8192)
        .map_err(|_| ErrorCode::InternalError)?;
    println!(
        "{}",
        std::str::from_utf8(&readiness).map_err(|_| ErrorCode::InternalError)?
    );
    let result = tokio::select! {
        _ = terminate.recv() => Ok(()), _ = interrupt.recv() => Ok(()),
        stopped = listeners.join_next() => Err(match stopped { Some(Ok((code, _))) => code, _ => ErrorCode::InternalError }.into()),
    };
    let deadline = Instant::now() + retirement::BUDGET;
    shutdown.cancel();
    let revoked = control.shutdown();
    listeners.abort_all();
    let _ = tokio::time::timeout_at(deadline.into(), async {
        while listeners.join_next().await.is_some() {}
    })
    .await;
    let retired = control.wait_retirement(deadline).await;
    let locked = store.lock().await.map_err(Into::into);
    drop((control_binding, observation_binding, lock));
    result.and(revoked).and(retired).and(locked)
}
