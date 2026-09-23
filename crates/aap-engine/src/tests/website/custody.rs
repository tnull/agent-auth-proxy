use super::*;

#[tokio::test]
async fn held_website_response_rechecks_custody_before_delivery() {
    custody_boundary(false).await;
}

#[tokio::test]
async fn held_website_response_rechecks_custody_before_completion() {
    custody_boundary(true).await;
}

async fn custody_boundary(delivered: bool) {
    for encoding in [LoginEncoding::Form, LoginEncoding::Json] {
        for change in ["none", "lock", "rotate", "delete"] {
            let mut fixture = Fixture::new().await;
            fixture.origin = website_origin(encoding, true).await;
            let broker = Broker::new(website_configuration(&fixture, encoding).await).unwrap();
            let session = broker.create_session(options()).unwrap();
            let login = session.get_login(issuance(&fixture)).await.unwrap();
            let csrf = page(&fixture, &session, &login).await;
            let input = request(
                &fixture,
                &login,
                "POST",
                "/session",
                &login_body(&login, &csrf, encoding),
            );
            let id = input.request_id.clone();
            let mut body = session.execute(input).await.unwrap().into_body();
            if delivered {
                assert!(
                    !body
                        .frame()
                        .await
                        .unwrap()
                        .unwrap()
                        .into_data()
                        .unwrap()
                        .is_empty()
                );
            }
            let reference = ItemRef::new("private-reference".into()).unwrap();
            let lease = fixture.store.metadata(&reference).await.unwrap().lease;
            match change {
                "lock" => fixture.store.lock().await.unwrap(),
                "rotate" => {
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
                                    SecretBytes::new(b"rotated-password".to_vec()).unwrap(),
                                ),
                            ]
                            .into(),
                            Some(&lease),
                        )
                        .await
                        .unwrap();
                }
                "delete" => fixture.store.delete(&reference, &lease).await.unwrap(),
                _ => {}
            }
            if change == "none" {
                body.collect().await.unwrap();
                assert_eq!(
                    session.request_status(id).await.unwrap().state,
                    OperationState::Completed
                );
                session
                    .execute(request(&fixture, &login, "GET", "/protected", b""))
                    .await
                    .unwrap()
                    .into_body()
                    .collect()
                    .await
                    .unwrap();
                assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
            } else {
                let frame = body.frame().await;
                assert!(
                    matches!(frame, Some(Err(_))),
                    "held website response accepted lost {change} custody at delivered={delivered}"
                );
                assert_eq!(
                    session.request_status(id.clone()).await.unwrap().state,
                    OperationState::OutcomeUnknown
                );
                crate::tests::completion::incomplete_endings(&fixture, &id);
                let context =
                    session.core.vault.lock().unwrap().contexts[&login.auth_context].clone();
                assert_eq!(context.state.lock().unwrap().status, AuthState::Revoked);
                assert!(context.state.lock().unwrap().csrf.is_none());
                assert!(
                    !context
                        .state
                        .lock()
                        .unwrap()
                        .jar
                        .has_all(&["session".into()], std::time::SystemTime::now())
                        .unwrap()
                );
                assert!(
                    session
                        .execute(request(&fixture, &login, "GET", "/protected", b""))
                        .await
                        .is_err()
                );
                assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
            }
            assert_eq!(
                fixture.resolutions.load(Ordering::SeqCst),
                1,
                "custody checks must not resolve another password"
            );
        }
    }
}
