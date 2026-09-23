use super::*;
use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn limits() -> Limits {
    Limits {
        max_chunk: 32 * 1024,
        send_limit: 32 * 1024 * 1024,
        receive_limit: 32 * 1024 * 1024,
        idle_timeout: Duration::from_secs(5),
        idle_deadline: Instant::now() + Duration::from_secs(5),
        lifetime: Instant::now() + Duration::from_secs(30),
    }
}

#[derive(Default)]
struct Recording {
    bytes: [Vec<u8>; 2],
    ends: [usize; 2],
}
struct Recorder(Arc<Mutex<Recording>>);
fn index(direction: Direction) -> usize {
    if direction == Direction::Outbound {
        0
    } else {
        1
    }
}
impl Gate for Recorder {
    fn before_forward(
        &mut self,
        direction: Direction,
        bytes: &[u8],
    ) -> std::result::Result<(), Cause> {
        self.0.lock().unwrap().bytes[index(direction)].extend_from_slice(bytes);
        Ok(())
    }
    fn before_end(&mut self, direction: Direction) -> std::result::Result<(), Cause> {
        self.0.lock().unwrap().ends[index(direction)] += 1;
        Ok(())
    }
}
fn recorder() -> Recorder {
    Recorder(Arc::new(Mutex::new(Recording::default())))
}

#[test]
fn only_fixed_local_attachment_errors_classify_terminal_causes() {
    use stream::service::AttachmentError;
    for failure in [
        AttachmentError::InvalidFrame,
        AttachmentError::LimitExceeded,
        AttachmentError::AttachmentLost,
        AttachmentError::InternalError,
    ] {
        let error = std::io::Error::other(failure);
        assert_eq!(io_error(0, &error), failure.cause());
        assert_eq!(io_error(1, &error), Cause::UpstreamUnavailable);
    }
    let error = std::io::Error::other("private native diagnostic");
    assert_eq!(io_error(0, &error), Cause::AttachmentLost);
    assert_eq!(io_error(1, &error), Cause::UpstreamUnavailable);
}

async fn pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    (client, listener.accept().await.unwrap().0)
}

#[tokio::test]
async fn binary_duplex_and_both_half_close_orders_use_real_sockets() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for upstream_first in [false, true] {
            let (mut client, local) = pair().await;
            let (upstream, mut server) = pair().await;
            let source = b"binary\0\xff\r\n";
            let greeting = b"hello\0\xff";
            let reply = b"after-end";
            let peer = tokio::spawn(async move {
                server.write_all(greeting).await.unwrap();
                if upstream_first {
                    server.shutdown().await.unwrap();
                }
                let mut bytes = Vec::new();
                server.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, source);
                if !upstream_first {
                    server.write_all(reply).await.unwrap();
                    server.shutdown().await.unwrap();
                }
            });
            let agent = tokio::spawn(async move {
                let mut first = [0; 7];
                client.read_exact(&mut first).await.unwrap();
                assert_eq!(&first, greeting);
                if upstream_first {
                    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
                }
                client.write_all(source).await.unwrap();
                client.shutdown().await.unwrap();
                let mut rest = Vec::new();
                client.read_to_end(&mut rest).await.unwrap();
                assert_eq!(
                    rest,
                    if upstream_first {
                        b"".as_slice()
                    } else {
                        reply.as_slice()
                    }
                );
            });
            let mut gate = recorder();
            let mut relay = Duplex::new(
                Box::new(local),
                Box::new(upstream),
                limits(),
                Cancellation::default(),
            )
            .unwrap();
            let outcome = poll_fn(|cx| relay.poll(cx, &mut gate)).await;
            assert_eq!(outcome.cause, Cause::OrderlyEnd);
            assert_eq!(outcome.sent_bytes, source.len() as u64);
            assert_eq!(
                outcome.received_bytes,
                (greeting.len() + if upstream_first { 0 } else { reply.len() }) as u64
            );
            agent.await.unwrap();
            peer.await.unwrap();
            let observed = gate.0.lock().unwrap();
            assert_eq!(observed.ends, [1, 1]);
            assert_eq!(observed.bytes[0], source);
            assert_eq!(observed.bytes[1].len() as u64, outcome.received_bytes);
        }
    })
    .await
    .unwrap();
}

struct DenyOrCancel {
    cancellation: Option<Cancellation>,
    calls: usize,
}
impl Gate for DenyOrCancel {
    fn before_forward(
        &mut self,
        _direction: Direction,
        _bytes: &[u8],
    ) -> std::result::Result<(), Cause> {
        self.calls += 1;
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
            Ok(())
        } else {
            Err(Cause::ObservationUnavailable)
        }
    }
    fn before_end(&mut self, _direction: Direction) -> std::result::Result<(), Cause> {
        Ok(())
    }
}

#[tokio::test]
async fn required_gate_failure_and_cancellation_precede_any_write() {
    for cancel in [false, true] {
        let (mut client, local) = tokio::io::duplex(64);
        let (upstream, mut server) = tokio::io::duplex(64);
        client.write_all(b"private synthetic bytes").await.unwrap();
        let cancellation = Cancellation::default();
        let mut gate = DenyOrCancel {
            cancellation: cancel.then(|| cancellation.clone()),
            calls: 0,
        };
        let mut relay =
            Duplex::new(Box::new(local), Box::new(upstream), limits(), cancellation).unwrap();
        let outcome = poll_fn(|cx| relay.poll(cx, &mut gate)).await;
        assert_eq!(
            outcome.cause,
            if cancel {
                Cause::Cancelled
            } else {
                Cause::ObservationUnavailable
            }
        );
        assert_eq!(outcome.sent_bytes, 0);
        assert_eq!(gate.calls, 1);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "unobserved or cancelled payload was forwarded"
        );
    }
}

async fn poll_pending(relay: &mut Duplex, gate: &mut dyn Gate) {
    poll_fn(|cx| {
        assert!(
            relay.poll(cx, gate).is_pending(),
            "relay ended before both directions closed"
        );
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn cancellation_counts_only_the_written_prefix_and_closes_retained_io() {
    let (mut client, local) = tokio::io::duplex(64);
    let (upstream, mut server) = tokio::io::duplex(3);
    client.write_all(b"abcdefgh").await.unwrap();
    let cancellation = Cancellation::default();
    let mut relay = Duplex::new(
        Box::new(local),
        Box::new(upstream),
        limits(),
        cancellation.clone(),
    )
    .unwrap();
    let mut gate = recorder();
    poll_pending(&mut relay, &mut gate).await;
    cancellation.cancel();
    let outcome = poll_fn(|cx| relay.poll(cx, &mut gate)).await;
    assert_eq!(
        outcome,
        Outcome {
            cause: Cause::Cancelled,
            sent_bytes: 3,
            received_bytes: 0
        }
    );
    let mut delivered = Vec::new();
    server.read_to_end(&mut delivered).await.unwrap();
    assert_eq!(delivered, b"abc");
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    let observations = gate.0.lock().unwrap().bytes[0].clone();
    assert_eq!(observations, b"abcdefgh");
    assert_eq!(poll_fn(|cx| relay.poll(cx, &mut gate)).await, outcome);
    assert_eq!(gate.0.lock().unwrap().bytes[0], observations);
}

#[tokio::test(start_paused = true)]
async fn opposite_direction_progress_does_not_extend_a_stalled_write() {
    let (mut client, local) = tokio::io::duplex(64);
    let (upstream, mut server) = tokio::io::duplex(1);
    client.write_all(b"blocked").await.unwrap();
    let mut relay = Duplex::new(
        Box::new(local),
        Box::new(upstream),
        limits(),
        Cancellation::default(),
    )
    .unwrap();
    let mut gate = recorder();
    poll_pending(&mut relay, &mut gate).await;
    tokio::time::advance(Duration::from_secs(4)).await;
    server.write_all(b"x").await.unwrap();
    poll_pending(&mut relay, &mut gate).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let outcome = poll_fn(|cx| relay.poll(cx, &mut gate)).await;
    assert_eq!(
        outcome,
        Outcome {
            cause: Cause::Timeout,
            sent_bytes: 1,
            received_bytes: 1
        }
    );
    let mut bytes = Vec::new();
    server.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"b");
}

#[tokio::test(start_paused = true)]
async fn activity_cannot_extend_lifetime_and_control_end_does_not_refresh_idle() {
    for lifetime in [false, true] {
        let (mut client, local) = tokio::io::duplex(64);
        let (upstream, _server) = tokio::io::duplex(64);
        let mut config = limits();
        if lifetime {
            config.lifetime = Instant::now() + Duration::from_secs(5);
        }
        let mut relay = Duplex::new(
            Box::new(local),
            Box::new(upstream),
            config,
            Cancellation::default(),
        )
        .unwrap();
        let mut gate = recorder();
        tokio::time::advance(Duration::from_secs(4)).await;
        if lifetime {
            client.write_all(b"progress").await.unwrap();
        } else {
            client.shutdown().await.unwrap();
        }
        poll_pending(&mut relay, &mut gate).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let outcome = poll_fn(|cx| relay.poll(cx, &mut gate)).await;
        assert_eq!(outcome.cause, Cause::Timeout);
        assert_eq!(outcome.sent_bytes, if lifetime { 8 } else { 0 });
    }
}

#[tokio::test]
async fn independent_byte_limits_stop_before_forwarding_excess() {
    for outbound in [false, true] {
        let (mut client, local) = tokio::io::duplex(64);
        let (upstream, mut server) = tokio::io::duplex(64);
        if outbound {
            client.write_all(b"abcd").await.unwrap();
        } else {
            server.write_all(b"abcd").await.unwrap();
        }
        let mut config = limits();
        if outbound {
            config.send_limit = 3;
        } else {
            config.receive_limit = 3;
        }
        let mut relay = Duplex::new(
            Box::new(local),
            Box::new(upstream),
            config,
            Cancellation::default(),
        )
        .unwrap();
        let mut gate = recorder();
        let outcome = poll_fn(|cx| relay.poll(cx, &mut gate)).await;
        assert_eq!(outcome.cause, Cause::LimitExceeded);
        assert_eq!(outcome.sent_bytes, if outbound { 3 } else { 0 });
        assert_eq!(outcome.received_bytes, if outbound { 0 } else { 3 });
        let mut delivered = Vec::new();
        if outbound {
            server.read_to_end(&mut delivered).await.unwrap();
        } else {
            client.read_to_end(&mut delivered).await.unwrap();
        }
        assert_eq!(delivered, b"abc");
    }
}

#[tokio::test]
async fn invalid_budgets_are_rejected_before_polling_sockets() {
    for which in 0..8 {
        let (local, _client) = tokio::io::duplex(1);
        let (upstream, _server) = tokio::io::duplex(1);
        let mut config = limits();
        match which {
            0 => config.max_chunk = 0,
            1 => config.max_chunk = 32 * 1024 + 1,
            2 => config.send_limit = 0,
            3 => config.receive_limit = 32 * 1024 * 1024 + 1,
            4 => config.idle_timeout = Duration::ZERO,
            5 => config.idle_timeout = Duration::from_secs(61),
            6 => config.lifetime = Instant::now() + Duration::from_secs(601),
            _ => config.idle_deadline = Instant::now() + Duration::from_secs(10),
        }
        assert!(
            Duplex::new(
                Box::new(local),
                Box::new(upstream),
                config,
                Cancellation::default()
            )
            .is_err(),
            "invalid budget {which} admitted"
        );
    }
}

struct AlwaysReady {
    polls: Arc<std::sync::atomic::AtomicUsize>,
    drops: Arc<std::sync::atomic::AtomicUsize>,
}
impl Drop for AlwaysReady {
    fn drop(&mut self) {
        self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
impl AsyncRead for AlwaysReady {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let remaining = buffer.remaining();
        buffer.initialize_unfilled().fill(b'x');
        buffer.advance(remaining);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for AlwaysReady {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn continuously_ready_peers_have_bounded_work_and_retained_payload() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let socket = || {
        Box::new(AlwaysReady {
            polls: polls.clone(),
            drops: drops.clone(),
        }) as TcpSocket
    };
    let cancellation = Cancellation::default();
    let mut relay = Duplex::new(socket(), socket(), limits(), cancellation.clone()).unwrap();
    let mut gate = recorder();
    assert_eq!(
        relay
            .directions
            .iter()
            .map(|state| state.buffer.len())
            .sum::<usize>(),
        64 * 1024
    );
    poll_pending(&mut relay, &mut gate).await;
    assert!(
        polls.load(Ordering::SeqCst) <= 16,
        "one poll monopolized ready I/O"
    );
    for direction in 0..2 {
        assert!(
            relay.directions[direction].forwarded > 0,
            "a direction was starved"
        );
        assert!(relay.directions[direction].forwarded <= 4 * 32 * 1024);
    }
    cancellation.cancel();
    assert_eq!(
        poll_fn(|cx| relay.poll(cx, &mut gate)).await.cause,
        Cause::Cancelled
    );
    assert_eq!(
        drops.load(Ordering::SeqCst),
        2,
        "terminal relay retained its I/O"
    );
    assert!(relay.directions.iter().all(|state| state.buffer.is_empty()));
    // Pre-cancelled and already expired owners do not even poll their sockets.
    for cancel in [false, true] {
        let before = polls.load(Ordering::SeqCst);
        let mut config = limits();
        let cancellation = Cancellation::default();
        if cancel {
            cancellation.cancel();
        } else {
            config.idle_deadline = Instant::now();
        }
        let mut relay = Duplex::new(socket(), socket(), config, cancellation).unwrap();
        assert_eq!(
            poll_fn(|cx| relay.poll(cx, &mut gate)).await.cause,
            if cancel {
                Cause::Cancelled
            } else {
                Cause::Timeout
            }
        );
        assert_eq!(polls.load(Ordering::SeqCst), before);
    }
}

struct Notifying(Arc<tokio::sync::Notify>);
impl Gate for Notifying {
    fn before_forward(
        &mut self,
        _direction: Direction,
        _bytes: &[u8],
    ) -> std::result::Result<(), Cause> {
        self.0.notify_one();
        Ok(())
    }
    fn before_end(&mut self, _direction: Direction) -> std::result::Result<(), Cause> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_and_deadline_wake_a_driver_blocked_on_both_peers() {
    for cancel in [false, true] {
        let (mut client, local) = tokio::io::duplex(64);
        let (upstream, mut server) = tokio::io::duplex(3);
        client.write_all(b"abcdefgh").await.unwrap();
        let cancellation = Cancellation::default();
        let mut relay = Duplex::new(
            Box::new(local),
            Box::new(upstream),
            limits(),
            cancellation.clone(),
        )
        .unwrap();
        let observed = Arc::new(tokio::sync::Notify::new());
        let mut gate = Notifying(observed.clone());
        let driver = tokio::spawn(async move { poll_fn(|cx| relay.poll(cx, &mut gate)).await });
        observed.notified().await;
        if cancel {
            cancellation.cancel();
        } else {
            tokio::time::advance(Duration::from_secs(5)).await;
        }
        let outcome = tokio::time::timeout(Duration::from_secs(1), driver)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome.cause,
            if cancel {
                Cause::Cancelled
            } else {
                Cause::Timeout
            }
        );
        assert_eq!(outcome.sent_bytes, 3);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"abc");
    }
}

struct EndFailure;
impl Gate for EndFailure {
    fn before_forward(
        &mut self,
        _direction: Direction,
        _bytes: &[u8],
    ) -> std::result::Result<(), Cause> {
        Ok(())
    }
    fn before_end(&mut self, _direction: Direction) -> std::result::Result<(), Cause> {
        Err(Cause::ObservationUnavailable)
    }
}

#[tokio::test]
async fn exact_limits_allow_orderly_end_but_end_observation_cannot_be_skipped() {
    for failure in [false, true] {
        let (mut client, local) = tokio::io::duplex(64);
        let (upstream, mut server) = tokio::io::duplex(64);
        client.write_all(b"abc").await.unwrap();
        server.write_all(b"defg").await.unwrap();
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
        let mut config = limits();
        config.send_limit = 3;
        config.receive_limit = 4;
        let mut relay = Duplex::new(
            Box::new(local),
            Box::new(upstream),
            config,
            Cancellation::default(),
        )
        .unwrap();
        let mut gate: Box<dyn Gate> = if failure {
            Box::new(EndFailure)
        } else {
            Box::new(recorder())
        };
        let outcome = poll_fn(|cx| relay.poll(cx, gate.as_mut())).await;
        assert_eq!(
            outcome.cause,
            if failure {
                Cause::ObservationUnavailable
            } else {
                Cause::OrderlyEnd
            }
        );
        assert_eq!(outcome.sent_bytes, 3);
        assert_eq!(outcome.received_bytes, 4);
    }
}

#[tokio::test]
async fn owner_termination_closes_unpolled_io_and_preserves_partial_counts() {
    let (mut client, local) = tokio::io::duplex(64);
    let (upstream, mut server) = tokio::io::duplex(3);
    client.write_all(b"abcdefgh").await.unwrap();
    let mut relay = Duplex::new(
        Box::new(local),
        Box::new(upstream),
        limits(),
        Cancellation::default(),
    )
    .unwrap();
    let mut gate = recorder();
    poll_pending(&mut relay, &mut gate).await;
    let outcome = relay.terminate(Cause::Cancelled);
    assert_eq!(
        outcome,
        Outcome {
            cause: Cause::Cancelled,
            sent_bytes: 3,
            received_bytes: 0
        }
    );
    let mut bytes = Vec::new();
    server.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"abc");
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(relay.terminate(Cause::Timeout), outcome);
    assert_eq!(poll_fn(|cx| relay.poll(cx, &mut gate)).await, outcome);
    let (local, _client) = tokio::io::duplex(1);
    let (upstream, _server) = tokio::io::duplex(1);
    let mut relay = Duplex::new(
        Box::new(local),
        Box::new(upstream),
        limits(),
        Cancellation::default(),
    )
    .unwrap();
    assert_eq!(
        relay.terminate(Cause::OrderlyEnd).cause,
        Cause::InternalError,
        "owner bypassed orderly-end checks"
    );
}
