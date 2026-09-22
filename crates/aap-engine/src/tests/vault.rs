use super::*;
use aap_types::profile::{CsrfProfile, LoginEncoding, LoginProfile, LoginSuccess};
use serde_json::json;

pub(super) async fn website_configuration(
    fixture: &Fixture,
    encoding: LoginEncoding,
) -> Configuration {
    let reference = ItemRef::new("private-reference".into()).unwrap();
    let metadata = fixture.store.metadata(&reference).await.unwrap();
    fixture
        .store
        .put(
            &reference,
            [
                (
                    Field::Username,
                    SecretBytes::new(b"private-user".to_vec()).unwrap(),
                ),
                (
                    Field::Password,
                    SecretBytes::new(b"private-password".to_vec()).unwrap(),
                ),
            ]
            .into(),
            Some(&metadata.lease),
        )
        .await
        .unwrap();
    let mut configuration = fixture.configuration();
    configuration.catalog.items[0].item_id = "work".into();
    configuration.catalog.items[0].label = "Work account".into();
    configuration.profiles[0].routes = [
        ("GET", "/login"),
        ("POST", "/session"),
        ("GET", "/protected"),
        ("POST", "/action"),
    ]
    .into_iter()
    .map(|(method, path)| Route {
        method: method.into(),
        path: path.into(),
        query: None,
        max_request_bytes: 256 * 1024,
        max_response_bytes: 256 * 1024,
        allowed_headers: vec!["content-type".into()],
        streaming: false,
        require_approval: false,
    })
    .collect();
    let (username, password, csrf) = match encoding {
        LoginEncoding::Form => ("user", "password", "csrf"),
        LoginEncoding::Json => ("/user", "/password", "/csrf"),
    };
    configuration.profiles[0].auth = Authentication::Form {
        login: LoginProfile {
            page: format!("{}/login", fixture.origin.origin()),
            target: format!("{}/session", fixture.origin.origin()),
            encoding,
            fields: CredentialFields {
                username: username.into(),
                password: password.into(),
            },
            username_visible: false,
            post_login_redirect: None,
            success: LoginSuccess {
                status: 200,
                cookie_names: vec!["session".into()],
                json_pointer: "/authenticated".into(),
                expected: json!(true),
            },
            csrf: Some(CsrfProfile {
                response_pointer: "/csrf".into(),
                submit_field: csrf.into(),
            }),
        },
    };
    configuration
}
pub(super) fn issuance(fixture: &Fixture) -> GetLogin {
    GetLogin {
        request_id: aap_types::ids::random_id(16).unwrap(),
        item_id: "work".into(),
        uri: format!("{}/login", fixture.origin.origin()),
    }
}
fn context(login: &Login) -> AuthContext {
    AuthContext {
        auth_context: login.auth_context.clone(),
    }
}

#[tokio::test]
async fn discovery_and_issuance_use_only_authorized_metadata_and_are_idempotent() {
    let fixture = Fixture::new().await;
    let mut configuration = website_configuration(&fixture, LoginEncoding::Form).await;
    configuration.catalog.items.push(Item {
        item_id: "personal".into(),
        account_alias: "personal".into(),
        label: "Personal".into(),
        ..configuration.catalog.items[0].clone()
    });
    let broker = Broker::new(configuration).unwrap();
    let mut grant = options();
    grant.items = Some(vec!["work".into()]);
    let session = broker.create_session(grant).unwrap();
    let search = session
        .search_items(SearchItems {
            uri: issuance(&fixture).uri,
            query: None,
            cursor: None,
        })
        .await
        .expect("catalog search is unsupported");
    assert_eq!(search.items.len(), 1);
    assert_eq!(search.items[0].item_id, "work");
    assert!(search.items[0].login_supported);
    let input = issuance(&fixture);
    let login = session
        .get_login(input.clone())
        .await
        .expect("fake credential issuance failed");
    assert_eq!(login.credentials.username.value.len(), 51);
    assert_eq!(login.credentials.password.value.len(), 51);
    assert!(login.credentials.username.value.starts_with("aap_un1_"));
    assert!(login.credentials.password.value.starts_with("aap_pw1_"));
    assert_eq!(
        login.submission.uri,
        format!("{}/session", fixture.origin.origin())
    );
    assert!(login.reusable);
    assert!(login.expires_in > 0 && login.expires_in <= 60);
    let duplicate = session.get_login(input.clone()).await.unwrap();
    assert_eq!(duplicate.auth_context, login.auth_context);
    assert_eq!(
        duplicate.credentials.password.value,
        login.credentials.password.value
    );
    assert_eq!(
        session
            .request_status(input.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::Completed
    );
    let mut changed = input.clone();
    changed.item_id = "personal".into();
    assert!(
        matches!(session.get_login(changed).await, Err(error) if error.code == ErrorCode::RequestConflict)
    );
    let mut unknown = issuance(&fixture);
    unknown.item_id = "personal".into();
    assert!(
        matches!(session.get_login(unknown).await, Err(error) if error.code == ErrorCode::PolicyDenied)
    );
    let mut cross_kind = fixture.request();
    cross_kind.request_id = input.request_id;
    assert!(
        matches!(session.execute(cross_kind).await, Err(error) if error.code == ErrorCode::RequestConflict)
    );
    let safe = serde_json::to_string(&login).unwrap();
    for secret in ["private-reference", "private-user", "private-password"] {
        assert!(!safe.contains(secret));
    }
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    assert!(
        session
            .search_items(SearchItems {
                uri: "https://fixture.test.evil/login".into(),
                query: None,
                cursor: None
            })
            .await
            .unwrap()
            .items
            .is_empty()
    );
}

#[tokio::test]
async fn contexts_are_session_bound_and_revoke_on_logout_rotation_or_store_lock() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(website_configuration(&fixture, LoginEncoding::Json).await).unwrap();
    let session = broker.create_session(options()).unwrap();
    let other = broker.create_session(options()).unwrap();
    let input = issuance(&fixture);
    let login = session
        .get_login(input.clone())
        .await
        .expect("issuance failed");
    assert_eq!(
        session.auth_status(context(&login)).await.unwrap().state,
        AuthState::Unauthenticated
    );
    assert!(
        matches!(other.auth_status(context(&login)).await, Err(error) if error.code == ErrorCode::PolicyDenied)
    );
    assert!(
        matches!(other.logout(context(&login)).await, Err(error) if error.code == ErrorCode::PolicyDenied)
    );
    for _ in 0..2 {
        assert_eq!(
            session.logout(context(&login)).await.unwrap().state,
            AuthState::Revoked
        );
    }
    assert_eq!(
        session.auth_status(context(&login)).await.unwrap().state,
        AuthState::Revoked
    );
    assert!(session.get_login(input).await.is_err());
    let next = session.get_login(issuance(&fixture)).await.unwrap();
    assert_ne!(login.auth_context, next.auth_context);
    let reference = ItemRef::new("private-reference".into()).unwrap();
    let metadata = fixture.store.metadata(&reference).await.unwrap();
    fixture
        .store
        .put(
            &reference,
            [
                (
                    Field::Username,
                    SecretBytes::new(b"changed-user".to_vec()).unwrap(),
                ),
                (
                    Field::Password,
                    SecretBytes::new(b"changed-password".to_vec()).unwrap(),
                ),
            ]
            .into(),
            Some(&metadata.lease),
        )
        .await
        .unwrap();
    assert_eq!(
        session.auth_status(context(&next)).await.unwrap().state,
        AuthState::Revoked
    );
    let fresh = session.get_login(issuance(&fixture)).await.unwrap();
    fixture.store.lock().await.unwrap();
    assert_eq!(
        session.auth_status(context(&fresh)).await.unwrap().state,
        AuthState::Revoked
    );
    assert!(
        matches!(session.get_login(issuance(&fixture)).await, Err(error) if error.code == ErrorCode::VaultLocked)
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    broker.revoke(&session).unwrap();
    assert!(session.auth_status(context(&fresh)).await.is_err());
}

#[tokio::test]
async fn discovery_pagination_is_bound_to_session_query_and_catalog_grants() {
    let fixture = Fixture::new().await;
    let mut configuration = website_configuration(&fixture, LoginEncoding::Form).await;
    configuration.catalog.items = (0..61)
        .map(|n| Item {
            item_id: format!("item-{n}"),
            label: format!("Account {n}"),
            ..configuration.catalog.items[0].clone()
        })
        .collect();
    let broker = Broker::new(configuration).unwrap();
    let session = broker.create_session(options()).unwrap();
    let other = broker.create_session(options()).unwrap();
    let query = SearchItems {
        uri: issuance(&fixture).uri,
        query: None,
        cursor: None,
    };
    let first = session
        .search_items(query.clone())
        .await
        .expect("search failed");
    assert_eq!(first.items.len(), 50);
    let next = SearchItems {
        cursor: first.next_cursor,
        ..query
    };
    assert!(next.cursor.is_some());
    let second = session.search_items(next.clone()).await.unwrap();
    assert_eq!(second.items.len(), 11);
    assert!(second.next_cursor.is_none());
    assert!(
        first
            .items
            .iter()
            .all(|item| second.items.iter().all(|next| next.item_id != item.item_id))
    );
    assert!(other.search_items(next.clone()).await.is_err());
    assert!(
        session
            .search_items(SearchItems {
                query: Some("different".into()),
                ..next
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn narrowed_item_grants_also_apply_to_provider_injection() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(fixture.configuration()).unwrap();
    let mut grant = options();
    grant.items = Some(Vec::new());
    let session = broker.create_session(grant).unwrap();
    assert!(
        matches!(session.execute(fixture.request()).await, Err(error) if error.code == ErrorCode::PolicyDenied),
        "provider bypassed the item grant"
    );
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    let mut unknown = options();
    unknown.items = Some(vec!["unknown".into()]);
    assert!(broker.create_session(unknown).is_err());
}

struct PausingStore {
    inner: Arc<SqliteStore>,
    pause: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
}
impl SecretStore for PausingStore {
    fn status(&self) -> BoxFuture<'_, aap_secrets::Result<aap_secrets::StoreStatus>> {
        self.inner.status()
    }
    fn metadata<'a>(
        &'a self,
        item: &'a ItemRef,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::ItemMetadata>> {
        self.inner.metadata(item)
    }
    fn resolve<'a>(
        &'a self,
        item: &'a ItemRef,
        lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<aap_secrets::Snapshot>> {
        self.inner.resolve(item, lease)
    }
    fn revalidate<'a>(
        &'a self,
        item: &'a ItemRef,
        lease: &'a aap_secrets::Lease,
    ) -> BoxFuture<'a, aap_secrets::Result<()>> {
        Box::pin(async move {
            if self.pause.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            self.inner.revalidate(item, lease).await
        })
    }
}
#[tokio::test]
async fn local_logout_during_revalidation_does_not_revoke_another_context() {
    let fixture = Fixture::new().await;
    let mut configuration = website_configuration(&fixture, LoginEncoding::Form).await;
    let store = Arc::new(PausingStore {
        inner: fixture.store.clone(),
        pause: std::sync::atomic::AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
    });
    configuration.stores.insert("default".into(), store.clone());
    let broker = Broker::new(configuration).unwrap();
    let session = broker.create_session(options()).unwrap();
    let first = session.get_login(issuance(&fixture)).await.unwrap();
    let second = session.get_login(issuance(&fixture)).await.unwrap();
    store.pause.store(true, Ordering::SeqCst);
    let running = session.clone();
    let first_context = context(&first);
    let checking = tokio::spawn(async move { running.auth_status(first_context).await });
    tokio::time::timeout(Duration::from_secs(2), store.entered.notified())
        .await
        .unwrap();
    session.logout(context(&first)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), checking)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .state,
        AuthState::Revoked
    );
    assert_eq!(
        session.auth_status(context(&second)).await.unwrap().state,
        AuthState::Unauthenticated,
        "local logout revoked an unrelated context"
    );
}

#[tokio::test]
async fn context_expiry_does_not_extend_on_retrieval_and_context_counts_are_bounded() {
    let fixture = Fixture::new().await;
    let broker = Broker::new(website_configuration(&fixture, LoginEncoding::Form).await).unwrap();
    let mut grant = options();
    grant.lifetime = Duration::from_secs(3600);
    let session = broker.create_session(grant).unwrap();
    let input = issuance(&fixture);
    let login = session.get_login(input.clone()).await.unwrap();
    for _ in 1..16 {
        session.get_login(issuance(&fixture)).await.unwrap();
    }
    assert!(
        matches!(session.get_login(issuance(&fixture)).await,Err(error) if error.code == ErrorCode::LimitExceeded)
    );
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(601)).await;
    assert_eq!(
        session.auth_status(context(&login)).await.unwrap().state,
        AuthState::Expired
    );
    assert!(session.get_login(input).await.is_err());
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}
