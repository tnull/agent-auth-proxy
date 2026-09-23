use super::*;
use aap_types::stream::service::Admission;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use stream::{Frame, Header, Sender, Sequence};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn send(peer: &mut tokio::io::DuplexStream, frame: Frame) {
    let encoded = frame.encode().unwrap();
    peer.write_all(&encoded.header).await.unwrap();
    peer.write_all(&encoded.payload).await.unwrap();
}
async fn next(peer: &mut tokio::io::DuplexStream, sequence: &mut Sequence) -> Frame {
    let mut header = [0; 5];
    peer.read_exact(&mut header).await.unwrap();
    let header = Header::parse(header).unwrap();
    sequence.check_header(Sender::Daemon, header).unwrap();
    let mut data = vec![0; header.length()];
    peer.read_exact(&mut data).await.unwrap();
    let frame = Frame::decode(header, data.into()).unwrap();
    sequence.accept(Sender::Daemon, &frame).unwrap();
    frame
}

#[tokio::test]
async fn tcp_framed_engine_orders_opening_and_binary_half_closes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for upstream_first in [false, true] {
            let fixture = Fixture::new().await;
            let tcp = TcpFixture::new().await;
            let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
            let session = broker.create_session(tcp_options()).unwrap();
            let request = open();
            let Admission::New(pending) = session.open_stream(request.clone()).await.unwrap()
            else {
                panic!()
            };
            let (mut peer, local) = tokio::io::duplex(4096);
            let service = tokio::spawn(aap_http::stream::serve_upgraded(
                local,
                request.clone(),
                pending,
            ));
            let upstream = tokio::spawn(async move {
                let (mut socket, _) = tcp.listener.accept().await.unwrap();
                socket.write_all(b"greet\0\xff").await.unwrap();
                if upstream_first {
                    socket.shutdown().await.unwrap();
                }
                let mut data = Vec::new();
                socket.read_to_end(&mut data).await.unwrap();
                assert_eq!(data, b"request\0\xfe");
                if !upstream_first {
                    socket.write_all(b"reply\0").await.unwrap();
                    socket.shutdown().await.unwrap();
                }
            });
            let mut sequence = Sequence::new(request.clone()).unwrap();
            assert!(matches!(
                next(&mut peer, &mut sequence).await,
                Frame::Opened(_)
            ));
            let mut inbound = Vec::new();
            while inbound.len() < 7 {
                let Frame::Data(data) = next(&mut peer, &mut sequence).await else {
                    panic!()
                };
                inbound.extend_from_slice(&data);
            }
            assert_eq!(inbound, b"greet\0\xff");
            if upstream_first {
                assert!(matches!(
                    next(&mut peer, &mut sequence).await,
                    Frame::SendEnd
                ));
            }
            for frame in [
                Frame::Data(Bytes::from_static(b"request\0\xfe")),
                Frame::SendEnd,
            ] {
                sequence.accept(Sender::Agent, &frame).unwrap();
                send(&mut peer, frame).await;
            }
            let terminal = loop {
                match next(&mut peer, &mut sequence).await {
                    Frame::Data(data) => inbound.extend_from_slice(&data),
                    Frame::SendEnd => {}
                    Frame::Terminal(value) => break value,
                    _ => panic!(),
                }
            };
            assert_eq!(terminal.operation.state, OperationState::Completed);
            assert_eq!(terminal.sent_bytes, 9);
            assert_eq!(
                inbound,
                if upstream_first {
                    b"greet\0\xff".as_slice()
                } else {
                    b"greet\0\xffreply\0".as_slice()
                }
            );
            assert_eq!(terminal.received_bytes, inbound.len() as u64);
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
            assert_eq!(service.await.unwrap().unwrap().cause, Cause::OrderlyEnd);
            upstream.await.unwrap();
            assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_framed_early_bytes_abort_before_connection_work() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let connector = Arc::new(MemoryConnector {
        peers: Mutex::new(vec![]),
        calls: AtomicUsize::new(0),
    });
    let mut config = tcp.configuration(&fixture);
    config.tcp_connector = connector.clone();
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    let Admission::New(pending) = session.open_stream(request.clone()).await.unwrap() else {
        panic!()
    };
    let (mut peer, local) = tokio::io::duplex(4096);
    peer.write_all(&[3]).await.unwrap();
    let service = tokio::spawn(aap_http::stream::serve_upgraded(
        local,
        request.clone(),
        pending,
    ));
    let mut sequence = Sequence::new(request).unwrap();
    let Frame::Terminal(terminal) = next(&mut peer, &mut sequence).await else {
        panic!()
    };
    assert_eq!(terminal.cause, Cause::InvalidFrame);
    assert_eq!(terminal.operation.state, OperationState::Failed);
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(service.await.unwrap().unwrap().cause, Cause::InvalidFrame);
}

#[tokio::test]
async fn tcp_framed_post_end_violation_interrupts_a_waiting_engine() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    let Admission::New(pending) = session.open_stream(request.clone()).await.unwrap() else {
        panic!()
    };
    let (mut peer, local) = tokio::io::duplex(4096);
    let service = tokio::spawn(aap_http::stream::serve_upgraded(
        local,
        request.clone(),
        pending,
    ));
    let mut sequence = Sequence::new(request).unwrap();
    assert!(matches!(
        next(&mut peer, &mut sequence).await,
        Frame::Opened(_)
    ));
    let (mut upstream, _) = tcp.listener.accept().await.unwrap();
    for frame in [Frame::Data(Bytes::from_static(b"sent")), Frame::SendEnd] {
        sequence.accept(Sender::Agent, &frame).unwrap();
        send(&mut peer, frame).await;
    }
    let mut written = Vec::new();
    upstream.read_to_end(&mut written).await.unwrap();
    assert_eq!(written, b"sent");
    // The relay now waits only on upstream input, not another application read.
    peer.write_all(&[3]).await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(2), next(&mut peer, &mut sequence))
        .await
        .unwrap();
    let Frame::Terminal(terminal) = frame else {
        panic!()
    };
    assert_eq!(terminal.cause, Cause::InvalidFrame);
    assert_eq!(terminal.operation.state, OperationState::OutcomeUnknown);
    assert_eq!(terminal.sent_bytes, 4);
    assert_eq!(service.await.unwrap().unwrap().cause, Cause::InvalidFrame);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

struct BlockOpening {
    written: usize,
    started: Arc<tokio::sync::Notify>,
}
impl tokio::io::AsyncRead for BlockOpening {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl tokio::io::AsyncWrite for BlockOpening {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let count = bytes.len().min(5 - self.written);
        if count == 0 {
            self.started.notify_one();
            return Poll::Pending;
        }
        self.written += count;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn tcp_framed_cancellation_interrupts_a_blocked_opening_frame() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let connector = Arc::new(MemoryConnector {
        peers: Mutex::new(vec![]),
        calls: AtomicUsize::new(0),
    });
    let mut config = tcp.configuration(&fixture);
    config.tcp_connector = connector;
    let broker = Broker::new(config).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    let Admission::New(pending) = session.open_stream(request.clone()).await.unwrap() else {
        panic!()
    };
    let started = Arc::new(tokio::sync::Notify::new());
    let driver = tokio::spawn(aap_http::stream::serve_upgraded(
        BlockOpening {
            written: 0,
            started: started.clone(),
        },
        request.clone(),
        pending,
    ));
    started.notified().await;
    tokio::time::pause();
    session.cancel(request.request_id).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), driver)
            .await
            .expect("cancelled operation kept a blocked OPENED writer alive")
            .unwrap()
            .is_err()
    );
    assert_eq!(session.core.active.available_permits(), 8);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_framed_pending_approval_has_no_payload_queue_or_late_revival() {
    for lost in [false, true] {
        let fixture = Fixture::new().await;
        let tcp = TcpFixture::new().await;
        let connector = Arc::new(MemoryConnector {
            peers: Mutex::new(vec![]),
            calls: AtomicUsize::new(0),
        });
        let (events, mut notices) = tokio::sync::mpsc::unbounded_channel();
        let mut config = tcp.configuration(&fixture);
        config.require_approval = true;
        config.approval = Some(Arc::new(ConnectionGate(events)));
        config.tcp_connector = connector.clone();
        let broker = Broker::new(config).unwrap();
        let session = broker.create_session(tcp_options()).unwrap();
        let request = open();
        let Admission::New(pending) = session.open_stream(request.clone()).await.unwrap() else {
            panic!()
        };
        let (mut peer, local) = tokio::io::duplex(4096);
        let service = tokio::spawn(aap_http::stream::serve_upgraded(
            local,
            request.clone(),
            pending,
        ));
        let (_, decide) = notices.recv().await.unwrap();
        assert_eq!(session.core.active.available_permits(), 8);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        if lost {
            peer.shutdown().await.unwrap();
        } else {
            peer.write_all(&[3]).await.unwrap();
        }
        let mut sequence = Sequence::new(request).unwrap();
        let Frame::Terminal(value) = next(&mut peer, &mut sequence).await else {
            panic!()
        };
        assert_eq!(
            value.cause,
            if lost {
                Cause::AttachmentLost
            } else {
                Cause::InvalidFrame
            }
        );
        assert_eq!(
            value.operation.state,
            if lost {
                OperationState::Cancelled
            } else {
                OperationState::Failed
            }
        );
        service.await.unwrap().unwrap();
        assert!(
            decide.send(true).is_err(),
            "abandoned approval could still revive its receiver"
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    }
}
