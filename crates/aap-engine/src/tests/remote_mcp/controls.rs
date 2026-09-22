use super::*;

async fn ping_fixture(ack_status: u16, ack_body: &'static str, cookie: bool) -> Fixture {
    let mut fixture = Fixture::new().await;
    fixture.origin = Origin::with_handler(move |request| {
        assert_eq!(request.headers["authorization"], "Bearer synthetic-api-key");
        let message: Value = serde_json::from_slice(&request.body).unwrap();
        if message.get("method").is_none() {
            assert_eq!(message["result"], json!({}));
            assert_eq!(message["id"], "private-server-ping-synthetic-api-key");
            // This must also work before initialization commits its session ID.
            assert_eq!(
                request.headers["mcp-session-id"],
                "private-remote-session-ping"
            );
            assert_eq!(request.headers["mcp-protocol-version"], VERSION);
            let mut reply = Reply::body(ack_body);
            reply.status = ack_status;
            if cookie {
                reply
                    .headers
                    .push(("set-cookie".into(), "private-cookie=value".into()));
            }
            return reply;
        }
        if message["method"] == "notifications/initialized" {
            let mut reply = Reply::body("");
            reply.status = 202;
            return reply;
        }
        let initializing = message["method"] == "initialize";
        let result = if initializing {
            json!({"protocolVersion":VERSION,"capabilities":{"tools":{}},
                "serverInfo":{"name":"fixture","version":"1"}})
        } else {
            assert_eq!(message["method"], "tools/call");
            json!({"content":[{"type":"text","text":"ok"}]})
        };
        let ping =
            json!({"jsonrpc":"2.0","id":"private-server-ping-synthetic-api-key","method":"ping"});
        let final_message = json!({"jsonrpc":"2.0","id":message["id"],"result":result});
        let mut reply = Reply::body(format!("data: {ping}\n\ndata: {final_message}\n\n"));
        reply
            .headers
            .push(("content-type".into(), "text/event-stream".into()));
        if initializing {
            reply.headers.push((
                "mcp-session-id".into(),
                "private-remote-session-ping".into(),
            ));
        }
        let body = reply.chunks.pop().unwrap();
        reply.chunks = body.chunks(11).map(Bytes::copy_from_slice).collect();
        reply
    })
    .await;
    fixture
}

#[tokio::test]
async fn remote_mcp_server_ping_uses_private_observed_child_dispatch() {
    let fixture = ping_fixture(202, "", false).await;
    let broker = Broker::new(configuration(&fixture)).unwrap();
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    let input = request(&fixture, call());
    let result = response_json(
        session
            .execute(input.clone())
            .await
            .expect("server ping reply"),
    )
    .await;
    assert_eq!(result["result"]["content"][0]["text"], "ok");
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 5);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 5);
    let records = fixture.recorder.read(None, 256).unwrap().records;
    let mut children = std::collections::BTreeSet::new();
    for record in records {
        if let Some(parent) = &record.event.parent_request_id {
            assert_ne!(record.event.request_id.as_ref(), Some(parent));
            children.insert(record.event.request_id.clone().unwrap());
        }
        let metadata = serde_json::to_string(&record).unwrap();
        assert!(!metadata.contains("private-remote-session"));
        assert!(!metadata.contains("private-server-ping"));
        assert!(!metadata.contains("synthetic-api-key"));
        if let aap_observe::Data::ContentChunk { body_base64, .. } = record.event.data {
            let bytes = STANDARD.decode(body_base64).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("private-remote-session"));
            assert!(!text.contains("private-server-ping"));
            assert!(!text.contains("synthetic-api-key"));
        }
    }
    assert_eq!(
        children.len(),
        2,
        "ping dispatches need distinct correlated flows"
    );
    for child in children {
        assert_eq!(
            session.request_status(child).await.unwrap().state,
            OperationState::Completed
        );
    }
}

struct ApproveParent(AtomicUsize);
impl ApprovalProvider for ApproveParent {
    fn approve(&self, _: Arc<ApprovalRequest>, _: Cancellation) -> BoxFuture<'_, Result<bool>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(true) })
    }
}

#[tokio::test]
async fn remote_mcp_server_ping_cannot_borrow_parent_approval() {
    let fixture = ping_fixture(202, "", false).await;
    let mut config = configuration(&fixture);
    config.catalog.items[0].approval = ItemApproval::Always;
    let approvals = Arc::new(ApproveParent(AtomicUsize::new(0)));
    config.approval = Some(approvals.clone());
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(options()).unwrap();
    handshake(&fixture, &session).await;
    response_json(session.execute(request(&fixture, call())).await.unwrap()).await;
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 3);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 3);
    assert_eq!(
        approvals.0.load(Ordering::SeqCst),
        3,
        "do not start child approval waits"
    );
    let records = fixture.recorder.read(None, 256).unwrap().records;
    assert!(
        records
            .iter()
            .any(|record| record.event.parent_request_id.is_some()
                && matches!(
                    record.event.data,
                    aap_observe::Data::PolicyDecision {
                        decision: aap_observe::Decision::Deny,
                        reason: Some(ErrorCode::InteractionUnavailable),
                    }
                )),
        "skipped child needs a safe policy reason"
    );
}

#[tokio::test]
async fn remote_mcp_server_ping_acknowledgment_must_be_empty_and_safe() {
    for (status, body, cookie) in [
        (200, "", false),
        (404, "", false),
        (202, "extra", false),
        (202, "", true),
    ] {
        let fixture = ping_fixture(status, body, cookie).await;
        let broker = Broker::new(configuration(&fixture)).unwrap();
        let session = broker.create_session(options()).unwrap();
        let input = request(&fixture, initialize());
        assert!(session.execute(input.clone()).await.is_err());
        assert_eq!(
            fixture.origin.requests.lock().unwrap().len(),
            2,
            "admitted ping must reach upstream before ACK validation"
        );
        assert_eq!(
            session
                .request_status(input.request_id)
                .await
                .unwrap()
                .state,
            OperationState::OutcomeUnknown
        );
        assert!(session.execute(request(&fixture, call())).await.is_err());
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
    }
}

struct WaitingChildResolver {
    address: SocketAddr,
    calls: AtomicUsize,
    entered: Arc<tokio::sync::Notify>,
}
impl Resolver for WaitingChildResolver {
    fn resolve<'a>(&'a self, _: &'a str, _: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(vec![self.address])
        })
    }
}

#[tokio::test]
async fn remote_mcp_server_ping_child_cancellation_interrupts_admission() {
    let fixture = ping_fixture(202, "", false).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let mut config = configuration(&fixture);
    config.resolver = Arc::new(WaitingChildResolver {
        address: fixture.origin.address,
        calls: AtomicUsize::new(0),
        entered: entered.clone(),
    });
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(options()).unwrap();
    let input = request(&fixture, initialize());
    let mut task = tokio::spawn({
        let session = session.clone();
        async move { session.execute(input).await }
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let child = fixture
        .recorder
        .read(None, 256)
        .unwrap()
        .records
        .into_iter()
        .find(|record| record.event.parent_request_id.is_some())
        .unwrap()
        .event
        .request_id
        .unwrap();
    assert_eq!(
        session.cancel(child.clone()).await.unwrap().state,
        OperationState::Cancelled
    );
    let result = tokio::time::timeout(Duration::from_millis(250), &mut task).await;
    task.abort();
    assert!(
        result.is_ok(),
        "child cancellation waited for the control timeout"
    );
    assert!(result.unwrap().unwrap().is_err());
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    assert_eq!(
        session.request_status(child).await.unwrap().state,
        OperationState::Cancelled
    );
}

#[tokio::test]
async fn remote_mcp_server_ping_uses_reserved_but_bounded_control_capacity() {
    for controls_full in [false, true] {
        let fixture = ping_fixture(202, "", false).await;
        let broker = Broker::new(configuration(&fixture)).unwrap();
        let session = broker.create_session(options()).unwrap();
        // Leave exactly one ordinary slot for initialization. A child must not
        // acquire another ordinary slot or bypass the two-slot control budget.
        let _ordinary = session
            .core
            .active
            .clone()
            .acquire_many_owned(7)
            .await
            .unwrap();
        let _controls = if controls_full {
            Some(
                session
                    .core
                    .control
                    .clone()
                    .acquire_many_owned(2)
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let result = session.execute(request(&fixture, initialize())).await;
        if controls_full {
            assert!(matches!(result, Err(error) if error.code == ErrorCode::LimitExceeded));
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
        } else {
            response_json(result.expect("reserved child capacity")).await;
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
            assert_eq!(fixture.origin.requests.lock().unwrap().len(), 2);
        }
        assert_eq!(session.core.active.available_permits(), 1);
        assert_eq!(
            session.core.remote_buffers.available_permits(),
            8 * 1024 * 1024
        );
    }
}

struct ChangeDuringChildAdmission {
    address: SocketAddr,
    calls: AtomicUsize,
    mode: u8,
    recorder: Recorder,
    store: Arc<SqliteStore>,
}
impl Resolver for ChangeDuringChildAdmission {
    fn resolve<'a>(&'a self, _: &'a str, _: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                match self.mode {
                    0 => {
                        return Ok(vec![SocketAddr::new(
                            "192.0.2.1".parse().unwrap(),
                            self.address.port(),
                        )]);
                    }
                    1 => self.recorder.set_available(false),
                    2 => {
                        let reference = ItemRef::new("private-reference".into()).unwrap();
                        let current = self.store.metadata(&reference).await.unwrap();
                        self.store
                            .put(
                                &reference,
                                [(
                                    Field::ApiKey,
                                    SecretBytes::new(b"rotated-key".to_vec()).unwrap(),
                                )]
                                .into(),
                                Some(&current.lease),
                            )
                            .await
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
            }
            Ok(vec![self.address])
        })
    }
}

#[tokio::test]
async fn remote_mcp_server_ping_rechecks_destination_recording_and_custody() {
    for mode in 0..3 {
        let fixture = ping_fixture(202, "", false).await;
        let mut config = configuration(&fixture);
        config.resolver = Arc::new(ChangeDuringChildAdmission {
            address: fixture.origin.address,
            calls: AtomicUsize::new(0),
            mode,
            recorder: fixture.recorder.clone(),
            store: fixture.store.clone(),
        });
        let broker = Broker::new(config).unwrap();
        let session = broker.create_session(options()).unwrap();
        let input = request(&fixture, initialize());
        assert!(session.execute(input.clone()).await.is_err());
        assert_eq!(
            fixture.origin.requests.lock().unwrap().len(),
            1,
            "child bypassed independent admission"
        );
        assert_eq!(
            session
                .request_status(input.request_id)
                .await
                .unwrap()
                .state,
            OperationState::OutcomeUnknown
        );
        if mode == 0 {
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 1);
        }
        fixture.recorder.set_available(true);
        assert!(session.execute(request(&fixture, call())).await.is_err());
        assert_eq!(fixture.origin.requests.lock().unwrap().len(), 1);
    }
}
