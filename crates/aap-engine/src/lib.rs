//! Trusted broker, separate from the credential-free session interface.
use aap_observe::Recorder;
use aap_policy::{Catalog, ResourceProfile};
use aap_secrets::SecretStore;
use aap_transport::{Cancellation, Resolver, Transport};
use aap_types::*;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

mod pipeline;
mod proxy;
mod vault;
mod website;

pub struct Configuration {
    pub catalog: Catalog,
    pub profiles: Vec<ResourceProfile>,
    pub stores: HashMap<String, Arc<dyn SecretStore>>,
    pub resolver: Arc<dyn Resolver>,
    pub transport: Arc<dyn Transport>,
    pub inspector: Arc<dyn aap_types::profile::RequestInspector>,
    pub approval: Option<Arc<dyn ApprovalProvider>>,
    pub require_approval: bool,
    pub recorder: Recorder,
}
pub struct SessionOptions {
    pub resources: Vec<String>,
    /// Optional narrowing to enrolled item aliases. None grants the items of
    /// the already permitted profiles; an empty list grants no credentials.
    pub items: Option<Vec<String>>,
    pub lifetime: Duration,
    pub require_approval: bool,
    pub require_observation: bool,
}
pub struct ApprovalRequest {
    pub daemon_epoch: String,
    pub session_id: String,
    pub approval_id: String,
    pub configuration_revision: u64,
    pub item_id: String,
    pub operation: Arc<ExecuteRequest>,
    pub credential_lease: aap_secrets::Lease,
    pub expires_at: std::time::Instant,
}
pub trait ApprovalProvider: Send + Sync {
    fn approve(
        &self,
        request: Arc<ApprovalRequest>,
        cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<bool>>;
}
pub struct Broker {
    host: Arc<Host>,
}
#[derive(Clone)]
pub struct Session {
    core: Arc<SessionCore>,
}
struct Host {
    configuration: Configuration,
    epoch: String,
    sessions: Mutex<HashMap<String, Weak<SessionCore>>>,
    operation_bytes: AtomicUsize,
    contexts: Arc<Semaphore>,
    login_attempts: Mutex<HashMap<String, Vec<Instant>>>,
}
struct SessionCore {
    host: Arc<Host>,
    id: String,
    options: SessionOptions,
    expires: Instant,
    cancelled: Cancellation,
    operations: Mutex<Operations>,
    active: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    pending_bytes: AtomicUsize,
    vault: Mutex<vault::Vault>,
}
#[derive(Default)]
struct Operations {
    items: HashMap<String, Arc<Operation>>,
    issuances: HashMap<String, Arc<vault::Issuance>>,
    bytes: usize,
}
struct Operation {
    request: Arc<ExecuteRequest>,
    state: Mutex<OperationStatus>,
    cancelled: Cancellation,
}
impl Operation {
    fn status(&self) -> Result<OperationStatus> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| ErrorCode::InternalError.into())
    }
    fn transition(&self, next: OperationState, status: Option<u16>) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
        if terminal(state.state) {
            return Err(ErrorCode::RequestConflict.into());
        }
        state.state = next;
        if status.is_some() {
            state.status = status;
        }
        Ok(())
    }
    fn cancel(&self) {
        if let Ok(mut state) = self.state.lock()
            && !terminal(state.state)
        {
            state.state = if state.state == OperationState::Dispatching {
                OperationState::OutcomeUnknown
            } else {
                OperationState::Cancelled
            };
            self.cancelled.cancel();
        }
    }
}
fn terminal(state: OperationState) -> bool {
    matches!(
        state,
        OperationState::Completed
            | OperationState::Failed
            | OperationState::OutcomeUnknown
            | OperationState::Denied
            | OperationState::Expired
            | OperationState::Cancelled
    )
}
impl Drop for SessionCore {
    fn drop(&mut self) {
        self.cancelled.cancel();
        let operations = self
            .operations
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.host
            .operation_bytes
            .fetch_sub(operations.bytes, Ordering::AcqRel);
    }
}
impl Broker {
    pub fn new(configuration: Configuration) -> Result<Self> {
        configuration.catalog.validate(
            &configuration.profiles,
            &configuration
                .stores
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            configuration.catalog.configuration_revision,
        )?;
        Ok(Self {
            host: Arc::new(Host {
                configuration,
                epoch: aap_types::ids::random_id(16).map_err(|_| ErrorCode::InternalError)?,
                sessions: Mutex::new(HashMap::new()),
                operation_bytes: AtomicUsize::new(0),
                contexts: Arc::new(Semaphore::new(64)),
                login_attempts: Mutex::new(HashMap::new()),
            }),
        })
    }
    pub fn create_session(&self, options: SessionOptions) -> Result<Session> {
        let mut resources = std::collections::HashSet::new();
        let mut items = std::collections::HashSet::new();
        if options.lifetime.is_zero()
            || options.lifetime > Duration::from_secs(3600)
            || options.resources.len() > 256
            || options.resources.iter().any(|resource| {
                !resources.insert(resource)
                    || !self
                        .host
                        .configuration
                        .profiles
                        .iter()
                        .any(|profile| &profile.id == resource)
            })
            || options.items.as_ref().is_some_and(|ids| {
                ids.len() > 1000
                    || ids.iter().any(|id| {
                        !items.insert(id)
                            || !self.host.configuration.catalog.items.iter().any(|item| {
                                &item.item_id == id && options.resources.contains(&item.profile)
                            })
                    })
            })
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let mut sessions = self
            .host
            .sessions
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        sessions.retain(|_, session| session.strong_count() > 0);
        if sessions.len() >= 64 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let id = aap_types::ids::random_id(16).map_err(|_| ErrorCode::InternalError)?;
        let core = Arc::new(SessionCore {
            host: self.host.clone(),
            id: id.clone(),
            expires: Instant::now() + options.lifetime,
            options,
            cancelled: Cancellation::default(),
            operations: Mutex::new(Operations::default()),
            active: Arc::new(Semaphore::new(8)),
            pending: Arc::new(Semaphore::new(16)),
            pending_bytes: AtomicUsize::new(0),
            vault: Mutex::new(vault::Vault::default()),
        });
        sessions.insert(id, Arc::downgrade(&core));
        Ok(Session { core })
    }
    pub fn revoke(&self, session: &Session) -> Result<()> {
        if !Arc::ptr_eq(&self.host, &session.core.host) {
            return Err(ErrorCode::PolicyDenied.into());
        }
        session.core.cancelled.cancel();
        for operation in session
            .core
            .operations
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .items
            .values()
        {
            operation.cancel();
        }
        for issuance in session
            .core
            .operations
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .issuances
            .values()
        {
            issuance.cancel();
        }
        for context in session
            .core
            .vault
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .contexts
            .values()
        {
            context.invalidate(AuthState::Revoked);
        }
        Ok(())
    }
}
impl Session {
    pub fn id(&self) -> &str {
        &self.core.id
    }
    fn check(&self) -> Result<()> {
        if self.core.cancelled.is_cancelled() || self.core.expires <= Instant::now() {
            Err(ErrorCode::SessionInvalid.into())
        } else {
            Ok(())
        }
    }
    fn operation(&self, id: &str) -> Result<Arc<Operation>> {
        self.check()?;
        self.core
            .operations
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .items
            .get(id)
            .cloned()
            .ok_or(ErrorCode::ResultUnavailable.into())
    }
}
impl AgentService for Session {
    fn execute(&self, request: ExecuteRequest) -> BoxFuture<'_, Result<Response>> {
        Box::pin(self.execute_inner(request))
    }
    fn forward(
        &self,
        request: aap_types::proxy::ForwardRequest,
    ) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async move { self.forward_inner(request).await })
    }
    fn search_items(&self, request: SearchItems) -> BoxFuture<'_, Result<SearchResult>> {
        Box::pin(async move { self.search_inner(request) })
    }
    fn get_login(&self, request: GetLogin) -> BoxFuture<'_, Result<Login>> {
        Box::pin(self.get_login_inner(request))
    }
    fn auth_status(&self, request: AuthContext) -> BoxFuture<'_, Result<AuthStatus>> {
        Box::pin(self.auth_status_inner(request))
    }
    fn logout(&self, request: AuthContext) -> BoxFuture<'_, Result<Logout>> {
        Box::pin(async move { self.logout_inner(request) })
    }
    fn request_status(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>> {
        Box::pin(async move {
            if let Some(issuance) = self.issuance(&request_id)? {
                return issuance.status();
            }
            self.operation(&request_id)?.status()
        })
    }
    fn cancel(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>> {
        Box::pin(async move {
            if let Some(issuance) = self.issuance(&request_id)? {
                issuance.cancel();
                return issuance.status();
            }
            let operation = self.operation(&request_id)?;
            operation.cancel();
            operation.status()
        })
    }
    fn admit_connect(&self, authority: String) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.admit_connect_inner(&authority).await })
    }
}

#[cfg(test)]
mod tests;
