use super::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[test]
fn endpoint_preserves_the_admitted_address_without_loosening_authority() {
    let address = "127.0.0.1:9000".parse().unwrap();
    let endpoint = TcpEndpoint::new("fixture.invalid:9000", address).unwrap();
    assert_eq!(endpoint.authority(), "fixture.invalid:9000");
    assert_eq!(endpoint.address(), address);
    for authority in [
        "fixture.invalid",
        "fixture.invalid:0",
        "Fixture.invalid:9000",
        "fixture.invalid:09000",
        "fixture.invalid:9001",
        "127.0.0.2:9000",
        "https://fixture.invalid:9000",
        "user@fixture.invalid:9000",
        "fixture.invalid:9000/path",
        "*.invalid:9000",
    ] {
        assert!(
            TcpEndpoint::new(authority, address).is_err(),
            "invalid authority accepted: {authority}"
        );
    }
    for address in [
        "0.0.0.0:9000",
        "224.0.0.1:9000",
        "[::]:9000",
        "[ff02::1]:9000",
    ] {
        assert!(TcpEndpoint::new("fixture.invalid:9000", address.parse().unwrap()).is_err());
    }
    let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "::1".parse().unwrap(),
        9000,
        0,
        7,
    ));
    assert!(TcpEndpoint::new("[::1]:9000", scoped).is_err());
    let address = "[::1]:9000".parse().unwrap();
    assert_eq!(
        TcpEndpoint::new("[::1]:9000", address).unwrap().address(),
        address
    );
}

#[tokio::test]
async fn a_single_admitted_connection_preserves_binary_and_both_half_close_orders() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for peer_ends_first in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                socket.write_all(b"greeting\0\xff").await.unwrap();
                if peer_ends_first {
                    socket.shutdown().await.unwrap();
                }
                let mut body = Vec::new();
                socket.read_to_end(&mut body).await.unwrap();
                assert_eq!(body, b"binary\0\xff\r\n");
                if !peer_ends_first {
                    socket.write_all(b"reply-after-eof").await.unwrap();
                    socket.shutdown().await.unwrap();
                }
            });
            // The supplied hostname need not resolve: only the admitted socket
            // address is dialed. These raw bytes are not TLS or local frames.
            let endpoint =
                TcpEndpoint::new(&format!("fixture.invalid:{}", address.port()), address).unwrap();
            let mut socket = SystemTcpConnector
                .connect(
                    endpoint,
                    Instant::now() + Duration::from_secs(2),
                    Cancellation::default(),
                )
                .await
                .unwrap();
            let mut greeting = [0; 10];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"greeting\0\xff");
            if peer_ends_first {
                let mut eof = [0];
                assert_eq!(socket.read(&mut eof).await.unwrap(), 0);
            }
            socket.write_all(b"binary\0\xff\r\n").await.unwrap();
            socket.shutdown().await.unwrap();
            let mut reply = Vec::new();
            socket.read_to_end(&mut reply).await.unwrap();
            assert_eq!(
                reply,
                if peer_ends_first {
                    b"".as_slice()
                } else {
                    b"reply-after-eof".as_slice()
                }
            );
            peer.await.unwrap();
        }
    })
    .await
    .unwrap();
}

struct DropCount(Arc<AtomicUsize>);
impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn admission_never_polls_cancelled_or_expired_attempts_and_late_success_is_dropped() {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let deadline = Instant::now() + Duration::from_secs(1);
    let ok = attempt(deadline, Cancellation::default(), async {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(DropCount(drops.clone()))
    })
    .await
    .unwrap();
    drop(ok);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    for (deadline, cancelled, expected) in [
        (deadline, true, ErrorCode::UpstreamUnavailable),
        (Instant::now(), false, ErrorCode::UpstreamUnavailable),
        (
            Instant::now() + Duration::from_secs(11),
            false,
            ErrorCode::RequestInvalid,
        ),
    ] {
        let cancellation = Cancellation::default();
        if cancelled {
            cancellation.cancel();
        }
        let result = attempt(deadline, cancellation, async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert_eq!(result.unwrap_err().code, expected);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "preflight polled the connector"
        );
    }
    let cancellation = Cancellation::default();
    let result = attempt(deadline, cancellation.clone(), async {
        calls.fetch_add(1, Ordering::SeqCst);
        cancellation.cancel();
        Ok(DropCount(drops.clone()))
    })
    .await;
    assert!(matches!(result, Err(error) if error.code == ErrorCode::OutcomeUnknown));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        2,
        "cancelled success leaked its socket"
    );
}

#[tokio::test(start_paused = true)]
async fn timeout_cancellation_failure_and_drop_never_repeat_or_detach_a_dial() {
    for mode in ["timeout", "cancel", "drop"] {
        let calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let cancellation = Cancellation::default();
        let (started, admitted) = tokio::sync::oneshot::channel();
        let task = {
            let calls = calls.clone();
            let drops = drops.clone();
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                attempt(
                    Instant::now() + Duration::from_secs(1),
                    cancellation,
                    async move {
                        let _guard = DropCount(drops);
                        calls.fetch_add(1, Ordering::SeqCst);
                        let _ = started.send(());
                        std::future::pending::<std::io::Result<()>>().await
                    },
                )
                .await
            })
        };
        admitted.await.expect("connection attempt did not start");
        match mode {
            "timeout" => tokio::time::advance(Duration::from_secs(1)).await,
            "cancel" => cancellation.cancel(),
            _ => task.abort(),
        }
        if mode == "drop" {
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                task.await.unwrap().unwrap_err().code,
                ErrorCode::OutcomeUnknown
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "pending connection was detached"
        );
    }
    let calls = AtomicUsize::new(0);
    let error = attempt::<()>(
        Instant::now() + Duration::from_secs(1),
        Cancellation::default(),
        async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("private-native-diagnostic"))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::OutcomeUnknown);
    assert!(!error.to_string().contains("private-native-diagnostic"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
