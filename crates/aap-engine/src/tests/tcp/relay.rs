use super::*;
use aap_observe::{Data, Direction, Inspection, Protocol, Redaction, View};
use base64::engine::general_purpose::STANDARD;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn tcp_engine_binary_half_close_and_redacted_ordered_views() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for inspection in [
            stream::Inspection::PlaintextBytes,
            stream::Inspection::Opaque,
            stream::Inspection::MetadataOnly,
        ] {
            for upstream_first in [false, true] {
                let mut fixture = Fixture::new().await;
                fixture.recorder = Recorder::new(
                    aap_types::ids::random_id(16).unwrap(),
                    1024,
                    4 * 1024 * 1024,
                )
                .unwrap();
                let tcp = TcpFixture::new().await;
                let mut config = tcp.configuration(&fixture);
                config.tcp_profiles[0].inspection = inspection;
                config.tcp_profiles[0].limits.max_data_bytes = 1;
                let broker = Broker::new(config).unwrap();
                let session = broker.create_session(tcp_options()).unwrap();
                let request = open();
                let connected = admitted(&session, request.clone()).connect().await.unwrap();
                let (mut server, _) = tcp.listener.accept().await.unwrap();
                let token = format!("aap_pw1_{}", aap_types::ids::random_id(32).unwrap());
                let source = format!("before:{token}:end\0").into_bytes();
                let expected = source.clone();
                let peer = tokio::spawn(async move {
                    server.write_all(b"hello\0\xff").await.unwrap();
                    if upstream_first {
                        server.shutdown().await.unwrap();
                    }
                    let mut data = Vec::new();
                    server.read_to_end(&mut data).await.unwrap();
                    assert_eq!(
                        data, expected,
                        "application bytes were redacted or reordered"
                    );
                    if !upstream_first {
                        server.write_all(&data).await.unwrap();
                        server.shutdown().await.unwrap();
                    }
                });
                let (mut client, local) = tokio::io::duplex(256);
                let outbound = source.clone();
                let agent = tokio::spawn(async move {
                    let mut greeting = [0; 7];
                    client.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(&greeting, b"hello\0\xff");
                    if upstream_first {
                        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
                    }
                    client.write_all(&outbound).await.unwrap();
                    client.shutdown().await.unwrap();
                    let mut reply = Vec::new();
                    client.read_to_end(&mut reply).await.unwrap();
                    assert_eq!(reply, if upstream_first { vec![] } else { outbound });
                });
                let outcome = connected.relay(Box::new(local)).await;
                assert_eq!(outcome.operation.state, OperationState::Completed);
                assert_eq!(outcome.cause, Cause::OrderlyEnd);
                assert_eq!(outcome.sent_bytes, source.len() as u64);
                assert_eq!(
                    outcome.received_bytes,
                    7 + if upstream_first {
                        0
                    } else {
                        source.len() as u64
                    }
                );
                outcome.validate().unwrap();
                peer.await.unwrap();
                agent.await.unwrap();
                assert_eq!(
                    session
                        .cancel(request.request_id.clone())
                        .await
                        .unwrap()
                        .state,
                    OperationState::Completed
                );
                assert_eq!(session.core.active.available_permits(), 8);
                assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
                let records = fixture.recorder.read(None, 1024).unwrap().records;
                let mut contents: HashMap<(Direction, View), Vec<u8>> = HashMap::new();
                let mut sequences: HashMap<String, u64> = HashMap::new();
                let mut ends = 0;
                let mut closes = 0;
                for record in records {
                    let event = record.event;
                    assert_eq!(event.protocol, Protocol::Tcp);
                    assert_eq!(event.session_id, session.id());
                    assert_eq!(
                        event.request_id.as_deref(),
                        Some(request.request_id.as_str())
                    );
                    let sequence = sequences.entry(event.stream_id).or_default();
                    assert_eq!(event.sequence, *sequence);
                    *sequence += 1;
                    match event.data {
                        Data::ContentChunk {
                            offset,
                            body_base64,
                            ..
                        } => {
                            let view = contents.entry((event.direction, event.view)).or_default();
                            assert_eq!(offset, view.len() as u64);
                            view.extend(STANDARD.decode(body_base64).unwrap());
                            assert_eq!(
                                event.inspection,
                                match inspection {
                                    stream::Inspection::PlaintextBytes =>
                                        Inspection::PlaintextBytes,
                                    stream::Inspection::Opaque => Inspection::Opaque,
                                    _ => Inspection::MetadataOnly,
                                }
                            );
                            if inspection == stream::Inspection::MetadataOnly {
                                assert_eq!(event.redaction, Redaction::Withheld);
                            }
                        }
                        Data::ContentEnd {
                            complete, bytes, ..
                        } => {
                            assert!(complete);
                            ends += 1;
                            assert_eq!(
                                bytes,
                                contents
                                    .entry((event.direction, event.view))
                                    .or_default()
                                    .len() as u64
                            );
                        }
                        Data::FlowClose {
                            complete,
                            outbound_bytes,
                            inbound_bytes,
                            ..
                        } => {
                            assert!(complete);
                            closes += 1;
                            assert_eq!(
                                (outbound_bytes, inbound_bytes),
                                (outcome.sent_bytes, outcome.received_bytes)
                            );
                        }
                        Data::RequestStart { .. }
                        | Data::ResponseStart { .. }
                        | Data::AuthTransition { .. } => {
                            panic!("invented a parsed credential-bearing exchange")
                        }
                        _ => {}
                    }
                }
                assert_eq!((ends, closes), (4, 2));
                for view in [View::Agent, View::Upstream] {
                    let expected_out = if inspection == stream::Inspection::MetadataOnly {
                        b"".as_slice()
                    } else {
                        b"before:[redacted]:end\0".as_slice()
                    };
                    assert_eq!(contents[&(Direction::Outbound, view)], expected_out);
                    let mut expected_in = if inspection == stream::Inspection::MetadataOnly {
                        vec![]
                    } else {
                        b"hello\0\xff".to_vec()
                    };
                    if !upstream_first {
                        expected_in.extend(expected_out);
                    }
                    assert_eq!(contents[&(Direction::Inbound, view)], expected_in);
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_required_recording_loss_prevents_new_payload_and_final_success() {
    for final_record in [false, true] {
        let mut fixture = Fixture::new().await;
        if final_record {
            fixture.recorder =
                Recorder::new(aap_types::ids::random_id(16).unwrap(), 10, 64 * 1024).unwrap();
        }
        let tcp = TcpFixture::new().await;
        let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
        let session = broker.create_session(tcp_options()).unwrap();
        let connected = admitted(&session, open()).connect().await.unwrap();
        let (mut server, _) = tcp.listener.accept().await.unwrap();
        let (mut client, local) = tokio::io::duplex(64);
        if final_record {
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        } else {
            fixture.recorder.set_available(false);
            client.write_all(b"blocked").await.unwrap();
        }
        let outcome = connected.relay(Box::new(local)).await;
        assert_eq!(outcome.cause, Cause::ObservationUnavailable);
        assert_eq!(outcome.operation.state, OperationState::OutcomeUnknown);
        assert_eq!((outcome.sent_bytes, outcome.received_bytes), (0, 0));
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
        assert_eq!(session.core.active.available_permits(), 8);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        fixture.recorder.set_available(true);
        assert!(
            !fixture
                .recorder
                .read(None, 32)
                .unwrap()
                .records
                .iter()
                .any(|record| matches!(record.event.data, Data::FlowClose { complete: true, .. }))
        );
    }
}

async fn memory_connection(
    idle_ms: u64,
    lifetime_ms: u64,
) -> (
    Fixture,
    Broker,
    Session,
    stream::Open,
    crate::tcp::ConnectedTcp,
    tokio::io::DuplexStream,
) {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let connector = Arc::new(MemoryConnector {
        peers: Mutex::new(vec![]),
        calls: AtomicUsize::new(0),
    });
    let mut config = tcp.configuration(&fixture);
    config.tcp_profiles[0].limits.idle_timeout_ms = idle_ms;
    config.tcp_profiles[0].limits.lifetime_ms = lifetime_ms;
    config.tcp_connector = connector.clone();
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    let connected = admitted(&session, request.clone()).connect().await.unwrap();
    let peer = connector.peers.lock().unwrap().pop().unwrap();
    (fixture, broker, session, request, connected, peer)
}
async fn pending(relay: &mut crate::tcp::TcpRelay) {
    poll_fn(|cx| {
        assert!(
            Pin::new(&mut *relay).poll(cx).is_pending(),
            "relay terminated before cancellation or both ends"
        );
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn tcp_cancellation_and_watchdog_close_retained_relays_with_partial_counts() {
    for expiry in [false, true] {
        let (fixture, broker, session, request, connected, mut server) =
            memory_connection(1000, 5000).await;
        let (mut client, local) = tokio::io::duplex(64);
        client.write_all(b"abcdefgh").await.unwrap();
        let mut relay = connected.relay(Box::new(local));
        pending(&mut relay).await;
        if expiry {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        } else {
            session.cancel(request.request_id.clone()).await.unwrap();
        }
        assert_eq!(
            session.core.active.available_permits(),
            8,
            "unpolled relay kept active capacity"
        );
        assert_eq!(broker.host.tcp_payload.available_permits(), 8 * 1024 * 1024);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"a");
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        let outcome = relay.await;
        assert_eq!(outcome.operation.state, OperationState::OutcomeUnknown);
        assert_eq!(
            outcome.cause,
            if expiry {
                Cause::Timeout
            } else {
                Cause::Cancelled
            }
        );
        assert_eq!((outcome.sent_bytes, outcome.received_bytes), (1, 0));
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        if expiry {
            tokio::time::resume();
        }
    }
}

#[tokio::test]
async fn tcp_progress_refreshes_watchdog_idle_but_never_connection_lifetime() {
    let (_fixture, _broker, session, request, connected, mut server) =
        memory_connection(1000, 2000).await;
    let (mut client, local) = tokio::io::duplex(64);
    let mut relay = connected.relay(Box::new(local));
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(800)).await;
    client.write_all(b"x").await.unwrap();
    pending(&mut relay).await;
    assert_eq!(server.read(&mut [0]).await.unwrap(), 1);
    tokio::time::advance(Duration::from_millis(300)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        session
            .request_status(request.request_id)
            .await
            .unwrap()
            .state,
        OperationState::Dispatching
    );
    tokio::time::advance(Duration::from_millis(500)).await;
    client.write_all(b"y").await.unwrap();
    pending(&mut relay).await;
    assert_eq!(server.read(&mut [0]).await.unwrap(), 1);
    tokio::time::advance(Duration::from_millis(400)).await;
    tokio::task::yield_now().await;
    assert_eq!(session.core.active.available_permits(), 8);
    let outcome = relay.await;
    assert_eq!(outcome.cause, Cause::Timeout);
    assert_eq!(outcome.sent_bytes, 2);
}

#[tokio::test]
async fn tcp_midstream_recording_loss_stops_required_but_not_best_effort_delivery() {
    for required in [false, true] {
        for inspection in [
            stream::Inspection::PlaintextBytes,
            stream::Inspection::MetadataOnly,
        ] {
            let fixture = Fixture::new().await;
            let tcp = TcpFixture::new().await;
            let connector = Arc::new(MemoryConnector {
                peers: Mutex::new(vec![]),
                calls: AtomicUsize::new(0),
            });
            let mut config = tcp.configuration(&fixture);
            config.tcp_connector = connector.clone();
            config.tcp_profiles[0].require_observation = required;
            config.tcp_profiles[0].inspection = inspection;
            let broker = Broker::new(config).unwrap();
            let mut options = tcp_options();
            options.require_observation = required;
            let session = broker.create_session(options).unwrap();
            let connected = admitted(&session, open()).connect().await.unwrap();
            let mut server = connector.peers.lock().unwrap().pop().unwrap();
            let (mut client, local) = tokio::io::duplex(64);
            let driver = tokio::spawn(connected.relay(Box::new(local)));
            client.write_all(b"x").await.unwrap();
            let mut byte = [0];
            server.read_exact(&mut byte).await.unwrap();
            assert_eq!(&byte, b"x");
            let before_loss = fixture.recorder.read(None, 32).unwrap().cursor;
            fixture.recorder.set_available(false);
            client.write_all(b"y").await.unwrap();
            if !required {
                server.read_exact(&mut byte).await.unwrap();
                assert_eq!(&byte, b"y");
                server.shutdown().await.unwrap();
                client.shutdown().await.unwrap();
            }
            let outcome = tokio::time::timeout(Duration::from_secs(2), driver)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                outcome.operation.state,
                if required {
                    OperationState::OutcomeUnknown
                } else {
                    OperationState::Completed
                }
            );
            assert_eq!(
                outcome.cause,
                if required {
                    Cause::ObservationUnavailable
                } else {
                    Cause::OrderlyEnd
                }
            );
            assert_eq!(outcome.sent_bytes, if required { 1 } else { 2 });
            assert_eq!(
                server.read(&mut byte).await.unwrap(),
                0,
                "required recording loss forwarded another byte"
            );
            fixture.recorder.set_available(true);
            assert!(
                fixture
                    .recorder
                    .read(Some(&before_loss), 32)
                    .unwrap()
                    .gap
                    .is_some()
            );
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn tcp_drop_and_revocation_release_held_relays_without_a_second_poll() {
    for revoke in [false, true] {
        let (fixture, broker, session, request, connected, mut server) =
            memory_connection(1000, 5000).await;
        let (mut client, local) = tokio::io::duplex(64);
        client.write_all(b"abcdef").await.unwrap();
        let mut relay = connected.relay(Box::new(local));
        pending(&mut relay).await;
        if revoke {
            broker.revoke(&session).unwrap();
            assert_eq!(session.core.active.available_permits(), 8);
            let outcome = relay.await;
            assert_eq!(outcome.cause, Cause::SessionEnded);
            assert_eq!(outcome.sent_bytes, 1);
        } else {
            drop(relay);
            assert_eq!(
                session
                    .request_status(request.request_id)
                    .await
                    .unwrap()
                    .state,
                OperationState::OutcomeUnknown
            );
        }
        assert_eq!(session.core.active.available_permits(), 8);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"a");
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        let closes = fixture
            .recorder
            .read(None, 32)
            .unwrap()
            .records
            .into_iter()
            .filter(|record| {
                matches!(
                    record.event.data,
                    Data::FlowClose {
                        complete: false,
                        outbound_bytes: 1,
                        inbound_bytes: 0,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(closes, 2);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    }
}

struct CancelOnEnd {
    inner: tokio::io::DuplexStream,
    cancellation: Cancellation,
}
impl tokio::io::AsyncRead for CancelOnEnd {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}
impl tokio::io::AsyncWrite for CancelOnEnd {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        if result.is_ready() {
            self.cancellation.cancel();
        }
        result
    }
}

#[tokio::test]
async fn tcp_ready_send_end_cancellation_cannot_commit_successful_observation() {
    let (fixture, _broker, session, request, connected, mut server) =
        memory_connection(1000, 5000).await;
    let (mut client, local) = tokio::io::duplex(64);
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
    let cancellation = session
        .tcp_operation(&request.request_id)
        .unwrap()
        .unwrap()
        .cancelled
        .clone();
    let outcome = connected
        .relay(Box::new(CancelOnEnd {
            inner: local,
            cancellation,
        }))
        .await;
    assert_eq!(outcome.cause, Cause::Cancelled);
    assert_eq!(outcome.operation.state, OperationState::OutcomeUnknown);
    assert!(
        !fixture
            .recorder
            .read(None, 32)
            .unwrap()
            .records
            .iter()
            .any(|record| matches!(record.event.data, Data::FlowClose { complete: true, .. }))
    );
}

struct SilentIo(Arc<AtomicUsize>);
impl tokio::io::AsyncRead for SilentIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
impl tokio::io::AsyncWrite for SilentIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
struct SilentConnector(Arc<AtomicUsize>);
impl aap_transport::tcp::TcpConnector for SilentConnector {
    fn connect(
        &self,
        _endpoint: aap_transport::tcp::TcpEndpoint,
        _deadline: Instant,
        _cancellation: Cancellation,
    ) -> BoxFuture<'_, Result<aap_transport::tcp::TcpSocket>> {
        Box::pin(async { Ok(Box::new(SilentIo(self.0.clone())) as aap_transport::tcp::TcpSocket) })
    }
}

#[tokio::test]
async fn tcp_session_watchdog_wakes_a_driver_with_no_socket_readiness() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let polls = Arc::new(AtomicUsize::new(0));
    let mut config = tcp.configuration(&fixture);
    config.tcp_connector = Arc::new(SilentConnector(polls.clone()));
    config.tcp_profiles[0].limits.idle_timeout_ms = 1000;
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let connected = admitted(&session, open()).connect().await.unwrap();
    let mut relay = connected.relay(Box::new(SilentIo(polls.clone())));
    pending(&mut relay).await;
    let driver = tokio::spawn(relay);
    tokio::task::yield_now().await;
    assert!(polls.load(Ordering::SeqCst) >= 4);
    tokio::time::pause();
    // Exercise the watchdog's session-cancellation path independently of the
    // operator's per-operation sweep. No I/O/drop or relay timer wakes it.
    session.core.cancelled.cancel();
    let outcome = tokio::time::timeout(Duration::from_millis(10), driver)
        .await
        .expect("watchdog closed I/O but lost the relay driver's waker")
        .unwrap();
    assert_eq!(outcome.cause, Cause::SessionEnded);
    assert_eq!(outcome.operation.state, OperationState::OutcomeUnknown);
}
