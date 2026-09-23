use super::*;
use aap_auth::{
    Redactor,
    cookies::CookieJar,
    login::{CsrfToken, Placeholders},
};
use aap_policy::{Authentication, Item, Target};
use aap_secrets::{Field, ItemRef, Lease};
use aap_types::profile::LoginEncoding;

#[derive(Default)]
pub(super) struct Vault {
    pub contexts: HashMap<String, Arc<Binding>>,
    cursors: HashMap<String, SearchCursor>,
    pub attempts: HashMap<String, Vec<Instant>>,
}
struct SearchCursor {
    uri: String,
    query: Option<String>,
    offset: usize,
}
pub(super) struct Binding {
    pub id: String,
    pub item: Item,
    pub lease: Lease,
    pub expires: Instant,
    pub cancelled: Cancellation,
    pub state: Mutex<BindingState>,
    pub exchange: Arc<Semaphore>,
    _permit: OwnedSemaphorePermit,
}
pub(super) struct BindingState {
    pub status: AuthState,
    pub values: Option<Placeholders>,
    pub jar: CookieJar,
    pub csrf: Option<CsrfToken>,
    pub template: Redactor,
}
impl Binding {
    pub fn invalidate(&self, status: AuthState) {
        if let Ok(mut state) = self.state.lock() {
            self.cancelled.cancel();
            state.status = status;
            state.values = None;
            state.jar.clear();
            state.csrf = None;
            if let Ok(empty) = Redactor::new(&[]) {
                state.template = empty;
            }
        } else {
            self.cancelled.cancel();
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.expires <= Instant::now() {
            let mut state = self.state.lock().map_err(|_| ErrorCode::InternalError)?;
            if state.status != AuthState::Revoked {
                state.status = AuthState::Expired;
                state.values = None;
                state.jar.clear();
                state.csrf = None;
                if let Ok(empty) = Redactor::new(&[]) {
                    state.template = empty;
                }
                self.cancelled.cancel();
            }
        }
        if self.cancelled.is_cancelled() {
            Err(ErrorCode::PlaceholderInvalid.into())
        } else {
            Ok(())
        }
    }
}
pub(super) struct Issuance {
    request: GetLogin,
    state: Mutex<IssuanceState>,
    cancelled: Cancellation,
}
struct IssuanceState {
    status: OperationStatus,
    result: Option<Result<String>>,
}
impl Issuance {
    pub fn status(&self) -> Result<OperationStatus> {
        self.state
            .lock()
            .map(|state| state.status.clone())
            .map_err(|_| ErrorCode::InternalError.into())
    }
    pub fn cancel(&self) {
        if let Ok(mut state) = self.state.lock()
            && !terminal(state.status.state)
        {
            self.cancelled.cancel();
            state.status.state = OperationState::Cancelled;
            state.result = Some(Err(ErrorCode::RequestConflict.into()));
        }
    }
}
struct IssueGuard {
    operation: Arc<Issuance>,
    finished: bool,
}
impl Drop for IssueGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.operation.cancel();
        }
    }
}

impl Session {
    pub(super) fn item_allowed(&self, item: &Item) -> bool {
        self.core.options.resources.contains(&item.profile)
            && self
                .core
                .options
                .items
                .as_ref()
                .is_none_or(|ids| ids.contains(&item.item_id))
    }
    pub(super) fn issuance(&self, id: &str) -> Result<Option<Arc<Issuance>>> {
        self.check()?;
        Ok(self
            .core
            .operations
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .issuances
            .get(id)
            .cloned())
    }
    pub(super) fn search_inner(&self, request: SearchItems) -> Result<SearchResult> {
        self.check()?;
        if request
            .query
            .as_ref()
            .is_some_and(|query| query.len() > 256)
            || request
                .cursor
                .as_ref()
                .is_some_and(|cursor| !aap_types::ids::valid_id(cursor, 32))
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let target = Target::parse(&request.uri)?;
        let mut vault = self
            .core
            .vault
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        let offset = match &request.cursor {
            Some(cursor) => {
                let cursor = vault.cursors.get(cursor).ok_or(ErrorCode::PolicyDenied)?;
                if cursor.uri != request.uri || cursor.query != request.query {
                    return Err(ErrorCode::PolicyDenied.into());
                }
                cursor.offset
            }
            None => 0,
        };
        let configuration = &self.core.host.configuration;
        let matching: Vec<_> = configuration
            .catalog
            .items
            .iter()
            .filter(|item| {
                self.item_allowed(item)
                    && request.query.as_ref().is_none_or(|query| {
                        item.label.contains(query) || item.account_alias.contains(query)
                    })
                    && configuration.profiles.iter().any(|profile| {
                        profile.id == item.profile
                            && profile.origin == target.origin()
                            && profile.routes.iter().any(|route| {
                                route.path == target.path()
                                    && route.query.as_deref() == target.query()
                            })
                    })
            })
            .collect();
        let items = matching.iter().skip(offset).take(50).map(|item| {
            let profile = configuration.profiles.iter().find(|profile| profile.id == item.profile).expect("validated catalog profile");
            ItemSummary { item_id: item.item_id.clone(), label: item.label.clone(), account_alias: item.account_alias.clone(), origins: vec![profile.origin.clone()], login_supported: matches!(&profile.auth, Authentication::Form { login } if !login.username_visible) }
        }).collect::<Vec<_>>();
        let next_offset = offset + items.len();
        let next_cursor = if next_offset < matching.len() {
            if let Some((id, _)) = vault.cursors.iter().find(|(_, cursor)| {
                cursor.uri == request.uri
                    && cursor.query == request.query
                    && cursor.offset == next_offset
            }) {
                Some(id.clone())
            } else {
                if vault.cursors.len() >= 64 {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                let id = aap_types::ids::random_id(32).map_err(|_| ErrorCode::InternalError)?;
                vault.cursors.insert(
                    id.clone(),
                    SearchCursor {
                        uri: request.uri,
                        query: request.query,
                        offset: next_offset,
                    },
                );
                Some(id)
            }
        } else {
            None
        };
        self.check()?;
        Ok(SearchResult { items, next_cursor })
    }
    pub(super) async fn get_login_inner(&self, request: GetLogin) -> Result<Login> {
        self.check()?;
        if !aap_types::ids::valid_id(&request.request_id, 16)
            || request.item_id.len() > 64
            || request.uri.len() > 16384
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let (operation, fresh) = {
            let mut operations = self
                .core
                .operations
                .lock()
                .map_err(|_| ErrorCode::InternalError)?;
            if operations.items.contains_key(&request.request_id)
                || operations.streams.contains_key(&request.request_id)
            {
                return Err(ErrorCode::RequestConflict.into());
            }
            if let Some(existing) = operations.issuances.get(&request.request_id) {
                if existing.request != request {
                    return Err(ErrorCode::RequestConflict.into());
                }
                (existing.clone(), false)
            } else {
                let bytes = request.uri.len() + request.item_id.len() + 2048;
                if operations.len() >= 4096 || operations.bytes + bytes > 8 * 1024 * 1024 {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                self.core
                    .host
                    .operation_bytes
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                        used.checked_add(bytes)
                            .filter(|next| *next <= 64 * 1024 * 1024)
                    })
                    .map_err(|_| ErrorCode::LimitExceeded)?;
                let operation = Arc::new(Issuance {
                    state: Mutex::new(IssuanceState {
                        status: OperationStatus {
                            request_id: request.request_id.clone(),
                            state: OperationState::Received,
                            status: None,
                        },
                        result: None,
                    }),
                    request,
                    cancelled: Cancellation::default(),
                });
                operations.bytes += bytes;
                operations
                    .issuances
                    .insert(operation.request.request_id.clone(), operation.clone());
                (operation, true)
            }
        };
        let mut guard = IssueGuard {
            operation: operation.clone(),
            finished: !fresh,
        };
        let result = if fresh {
            let deadline = self
                .core
                .expires
                .min(Instant::now() + Duration::from_secs(10));
            let prepared = tokio::select! {
                biased;
                _ = self.core.cancelled.cancelled() => Err(ErrorCode::SessionInvalid.into()),
                _ = operation.cancelled.cancelled() => Err(ErrorCode::RequestConflict.into()),
                result = tokio::time::timeout_at(deadline, self.prepare_binding(&operation.request)) => result.unwrap_or_else(|_| Err(ErrorCode::VaultUnavailable.into())),
            };
            let mut state = operation
                .state
                .lock()
                .map_err(|_| ErrorCode::InternalError)?;
            if terminal(state.status.state) {
                return Err(ErrorCode::RequestConflict.into());
            }
            let prepared = prepared.and_then(|binding| {
                self.check()?;
                binding.check()?;
                let mut vault = self
                    .core
                    .vault
                    .lock()
                    .map_err(|_| ErrorCode::InternalError)?;
                if vault.contexts.len() >= 16 {
                    return Err(ErrorCode::LimitExceeded.into());
                }
                let id = binding.id.clone();
                #[cfg(test)]
                self.before_publication(&operation.request.request_id);
                self.commit_authority(|| {
                    if operation.cancelled.is_cancelled() {
                        return Err(ErrorCode::RequestConflict.into());
                    }
                    if binding.cancelled.is_cancelled() || binding.expires <= Instant::now() {
                        return Err(ErrorCode::PlaceholderInvalid.into());
                    }
                    vault.contexts.insert(id.clone(), binding);
                    state.status.state = OperationState::Completed;
                    state.result = Some(Ok(id.clone()));
                    Ok(id)
                })
            });
            if let Err(error) = &prepared {
                state.status.state = match error.code {
                    ErrorCode::SessionInvalid => OperationState::Cancelled,
                    ErrorCode::PolicyDenied => OperationState::Denied,
                    _ => OperationState::Failed,
                };
                state.result = Some(Err(error.clone()));
            }
            guard.finished = true;
            prepared
        } else {
            operation
                .state
                .lock()
                .map_err(|_| ErrorCode::InternalError)?
                .result
                .clone()
                .ok_or(ErrorCode::AuthInProgress)?
        };
        let id = result.map_err(|error| error.for_request(&operation.request.request_id))?;
        let binding = self.binding(&id)?;
        self.revalidate_binding(&binding).await?;
        self.login_result(&binding)
    }
    async fn prepare_binding(&self, request: &GetLogin) -> Result<Arc<Binding>> {
        let _active = self
            .core
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::LimitExceeded)?;
        let configuration = &self.core.host.configuration;
        let item = configuration
            .catalog
            .items
            .iter()
            .find(|item| item.item_id == request.item_id && self.item_allowed(item))
            .ok_or(ErrorCode::PolicyDenied)?;
        let profile = configuration
            .profiles
            .iter()
            .find(|profile| profile.id == item.profile)
            .ok_or(ErrorCode::PolicyDenied)?;
        let Authentication::Form { login } = &profile.auth else {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        };
        if login.username_visible {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        let target = Target::parse(&request.uri)?;
        if target.as_str() != Target::parse(&login.page)?.as_str() {
            return Err(ErrorCode::PolicyDenied.into());
        }
        let permit = self
            .core
            .host
            .contexts
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::LimitExceeded)?;
        aap_observe::Flow::new(
            configuration.recorder.clone(),
            aap_observe::FlowContext {
                session_id: self.id().into(),
                request_id: Some(request.request_id.clone()),
                parent_request_id: None,
                policy_version: configuration.catalog.configuration_revision,
                protocol: aap_observe::Protocol::Control,
            },
            self.core.options.require_observation,
        )?
        .record(
            aap_observe::Direction::Outbound,
            aap_observe::View::Agent,
            aap_observe::Inspection::MetadataOnly,
            aap_observe::Redaction::Complete,
            aap_observe::Data::AuthTransition {
                item_id: item.item_id.clone(),
                inserted: false,
            },
        )?;
        let store = configuration
            .stores
            .get(&item.credential.store)
            .ok_or(ErrorCode::VaultUnavailable)?;
        let reference = ItemRef::new(item.credential.key.clone())?;
        let metadata = store.metadata(&reference).await?;
        if !metadata.fields.contains(&Field::Username)
            || !metadata.fields.contains(&Field::Password)
        {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        let mut expires = self
            .core
            .expires
            .min(Instant::now() + Duration::from_secs(600));
        if let Some(valid_until) = metadata.valid_until {
            expires = expires.min(Instant::from_std(valid_until));
        }
        if expires <= Instant::now() {
            return Err(ErrorCode::VaultUnavailable.into());
        }
        store.revalidate(&reference, &metadata.lease).await?;
        self.check()?;
        Ok(Arc::new(Binding {
            id: aap_types::ids::random_id(32).map_err(|_| ErrorCode::InternalError)?,
            item: item.clone(),
            lease: metadata.lease,
            expires,
            cancelled: Cancellation::default(),
            state: Mutex::new(BindingState {
                status: AuthState::Unauthenticated,
                values: Some(Placeholders::new()?),
                jar: CookieJar::new(&target),
                csrf: None,
                template: Redactor::new(&[])?,
            }),
            exchange: Arc::new(Semaphore::new(1)),
            _permit: permit,
        }))
    }
    pub(super) fn binding(&self, id: &str) -> Result<Arc<Binding>> {
        self.check()?;
        if !aap_types::ids::valid_id(id, 32) {
            return Err(ErrorCode::PolicyDenied.into());
        }
        self.core
            .vault
            .lock()
            .map_err(|_| ErrorCode::InternalError)?
            .contexts
            .get(id)
            .cloned()
            .ok_or(ErrorCode::PolicyDenied.into())
    }
    pub(super) async fn revalidate_binding(&self, binding: &Binding) -> Result<()> {
        self.check()?;
        binding.check()?;
        let store = self
            .core
            .host
            .configuration
            .stores
            .get(&binding.item.credential.store)
            .ok_or(ErrorCode::VaultUnavailable)?;
        let reference = ItemRef::new(binding.item.credential.key.clone())?;
        let result = tokio::select! {
            biased;
            _ = self.core.cancelled.cancelled() => Err(ErrorCode::SessionInvalid.into()),
            _ = binding.cancelled.cancelled() => Err(ErrorCode::PlaceholderInvalid.into()),
            result = tokio::time::timeout_at(binding.expires.min(Instant::now()+Duration::from_secs(10)), store.revalidate(&reference,&binding.lease)) => result.map_err(|_| ErrorCode::VaultUnavailable).and_then(|result| result.map_err(|error| Error::from(error).code)).map_err(Error::from),
        };
        if result.as_ref().is_err_and(|error| {
            matches!(
                error.code,
                ErrorCode::VaultLocked
                    | ErrorCode::VaultUnavailable
                    | ErrorCode::PolicyDenied
                    | ErrorCode::InteractionUnavailable
            )
        }) {
            self.invalidate_item(&binding.item.item_id)?;
        }
        result?;
        self.check()?;
        binding.check()
    }
    fn invalidate_item(&self, id: &str) -> Result<()> {
        let vault = self
            .core
            .vault
            .lock()
            .map_err(|_| ErrorCode::InternalError)?;
        for binding in vault
            .contexts
            .values()
            .filter(|binding| binding.item.item_id == id)
        {
            binding.invalidate(AuthState::Revoked);
        }
        Ok(())
    }
    fn login_result(&self, binding: &Binding) -> Result<Login> {
        self.check()?;
        binding.check()?;
        let profile = self
            .core
            .host
            .configuration
            .profiles
            .iter()
            .find(|profile| profile.id == binding.item.profile)
            .ok_or(ErrorCode::PolicyDenied)?;
        let Authentication::Form { login } = &profile.auth else {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        };
        let state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
        let values = state.values.as_ref().ok_or(ErrorCode::PlaceholderInvalid)?;
        Ok(Login {
            item_id: binding.item.item_id.clone(),
            auth_context: binding.id.clone(),
            credentials: Credentials {
                username: CredentialValue {
                    value: values.username().into(),
                    kind: CredentialKind::Placeholder,
                },
                password: CredentialValue {
                    value: values.password().into(),
                    kind: CredentialKind::Placeholder,
                },
            },
            submission: Submission {
                uri: login.target.clone(),
                method: "POST".into(),
                content_type: match login.encoding {
                    LoginEncoding::Form => "application/x-www-form-urlencoded",
                    LoginEncoding::Json => "application/json",
                }
                .into(),
                fields: login.fields.clone(),
            },
            expires_in: binding
                .expires
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1),
            reusable: true,
        })
    }
    pub(super) async fn auth_status_inner(&self, request: AuthContext) -> Result<AuthStatus> {
        let binding = self.binding(&request.auth_context)?;
        if binding.check().is_ok() {
            let _ = self.revalidate_binding(&binding).await;
        }
        self.check()?;
        let state = binding.state.lock().map_err(|_| ErrorCode::InternalError)?;
        Ok(AuthStatus {
            item_id: binding.item.item_id.clone(),
            account_alias: binding.item.account_alias.clone(),
            state: state.status,
        })
    }
    pub(super) fn logout_inner(&self, request: AuthContext) -> Result<Logout> {
        let binding = self.binding(&request.auth_context)?;
        binding.invalidate(AuthState::Revoked);
        Ok(Logout {
            state: AuthState::Revoked,
            remote_logout: RemoteLogout::NotSupported,
        })
    }
}
