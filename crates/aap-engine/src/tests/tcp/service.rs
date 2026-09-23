use super::*;
use aap_types::stream::service::{Admission, ApplicationIo, AttachmentError, Connection};
use std::future::poll_fn;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct Attachment(tokio::io::DuplexStream);
impl ApplicationIo for Attachment {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        let mut buffer = tokio::io::ReadBuf::new(buffer);
        match Pin::new(&mut self.0).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(AttachmentError::AttachmentLost)),
        }
    }
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        Pin::new(&mut self.0)
            .poll_write(cx, bytes)
            .map_err(|_| AttachmentError::AttachmentLost)
    }
    fn poll_send_end(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), AttachmentError>> {
        Pin::new(&mut self.0)
            .poll_shutdown(cx)
            .map_err(|_| AttachmentError::AttachmentLost)
    }
}

#[tokio::test]
async fn tcp_service_abort_interrupts_unpolled_work_without_rewriting_terminal() {
    for connected_phase in [false, true] {
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
        let abort = pending.abort_handle();
        let terminal = if connected_phase {
            let Connection::Opened(connected) = pending.connect().await.unwrap() else {
                panic!()
            };
            let connected_abort = connected.abort_handle();
            let (mut client, local) = tokio::io::duplex(64);
            client.write_all(b"abc").await.unwrap();
            let mut relay = connected.relay(Box::new(Attachment(local)));
            poll_fn(|cx| {
                assert!(relay.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            connected_abort.abort(AttachmentError::InvalidFrame);
            assert_eq!(session.core.active.available_permits(), 8);
            relay.await.unwrap()
        } else {
            let mut connection = pending.connect();
            abort.abort(AttachmentError::InvalidFrame);
            assert_eq!(
                session
                    .request_status(request.request_id.clone())
                    .await
                    .unwrap()
                    .state,
                OperationState::Failed,
                "stop-only handle did not terminate pending work"
            );
            let value = poll_fn(|cx| {
                let result = connection.as_mut().poll(cx);
                assert!(
                    result.is_ready(),
                    "aborted pending operation started connection work"
                );
                result
            })
            .await
            .unwrap();
            let Connection::Terminal(terminal) = value else {
                panic!()
            };
            terminal
        };
        assert_eq!(terminal.cause, Cause::InvalidFrame);
        assert_eq!(terminal.sent_bytes, if connected_phase { 1 } else { 0 });
        assert_eq!(
            terminal.operation.state,
            if connected_phase {
                OperationState::OutcomeUnknown
            } else {
                OperationState::Failed
            }
        );
        abort.abort(AttachmentError::LimitExceeded);
        let retained = session.request_status(request.request_id).await.unwrap();
        assert_eq!(retained.state, terminal.operation.state);
        assert_eq!(retained.request_id, terminal.operation.request_id);
        assert_eq!(retained.status, terminal.operation.status);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(
            connector.calls.load(Ordering::SeqCst),
            usize::from(connected_phase)
        );
    }
}

#[tokio::test]
async fn tcp_service_admission_preserves_identity_and_does_not_connect() {
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
    let service: &dyn AgentService = &session;
    let request = open();
    let Admission::New(pending) = service.open_stream(request.clone()).await.unwrap() else {
        panic!("new operation returned existing status");
    };
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert!(
        matches!(service.open_stream(request.clone()).await.unwrap(), Admission::Existing(status) if status.state == OperationState::Validated)
    );
    let mut conflicting = request.clone();
    conflicting.resource = "elsewhere".into();
    assert!(matches!(
        service.open_stream(conflicting).await,
        Err(Error {
            code: ErrorCode::RequestConflict,
            ..
        })
    ));
    drop(pending);
    assert!(
        matches!(service.open_stream(request).await.unwrap(), Admission::Existing(status) if status.state == OperationState::Cancelled)
    );
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(session.core.tcp_pending.available_permits(), 16);
}

#[tokio::test]
async fn tcp_service_forwards_binary_and_separates_end_from_terminal() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let service: &dyn AgentService = &session;
    let request = open();
    let Admission::New(pending) = service.open_stream(request.clone()).await.unwrap() else {
        panic!()
    };
    let Connection::Opened(connected) = pending.connect().await.unwrap() else {
        panic!()
    };
    assert_eq!(connected.opened().unwrap().request_id, request.request_id);
    let (mut upstream, _) = tcp.listener.accept().await.unwrap();
    let peer = tokio::spawn(async move {
        let mut data = Vec::new();
        upstream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"\0\xff request");
        upstream.write_all(b"reply\0\xfe").await.unwrap();
        upstream.shutdown().await.unwrap();
    });
    let (mut client, local) = tokio::io::duplex(64);
    let relay = tokio::spawn(connected.relay(Box::new(Attachment(local))));
    client.write_all(b"\0\xff request").await.unwrap();
    client.shutdown().await.unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"reply\0\xfe");
    let terminal = relay.await.unwrap().unwrap();
    assert_eq!(terminal.operation.state, OperationState::Completed);
    assert_eq!(terminal.cause, Cause::OrderlyEnd);
    assert_eq!((terminal.sent_bytes, terminal.received_bytes), (10, 7));
    terminal.validate().unwrap();
    peer.await.unwrap();
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_service_relay_transfer_is_owned_before_first_poll() {
    let fixture = Fixture::new().await;
    let tcp = TcpFixture::new().await;
    let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
    let session = broker.create_session(tcp_options()).unwrap();
    let request = open();
    let Admission::New(pending) = session.open_stream(request.clone()).await.unwrap() else {
        panic!()
    };
    let Connection::Opened(connected) = pending.connect().await.unwrap() else {
        panic!()
    };
    let (mut upstream, _) = tcp.listener.accept().await.unwrap();
    let (mut client, local) = tokio::io::duplex(64);
    let relay = connected.relay(Box::new(Attachment(local)));
    session.cancel(request.request_id).await.unwrap();
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(upstream.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(session.core.active.available_permits(), 8);
    assert_eq!(relay.await.unwrap().cause, Cause::Cancelled);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_service_connection_failure_and_abandonment_never_reconnect() {
    for abandon in [false, true] {
        let fixture = Fixture::new().await;
        let tcp = TcpFixture::new().await;
        let mut config = tcp.configuration(&fixture);
        config.tcp_profiles[0].require_approval = true;
        let broker = Broker::new(config).unwrap();
        let session = broker.create_session(tcp_options()).unwrap();
        let request = open();
        let Admission::New(pending) = session.open_stream(request.clone()).await.unwrap() else {
            panic!()
        };
        let connection = pending.connect();
        if abandon {
            drop(connection);
        } else {
            let Connection::Terminal(terminal) = connection.await.unwrap() else {
                panic!()
            };
            assert_eq!(terminal.cause, Cause::InteractionUnavailable);
            assert_eq!(terminal.operation.state, OperationState::Failed);
            terminal.validate().unwrap();
        }
        let Admission::Existing(status) = session.open_stream(request).await.unwrap() else {
            panic!()
        };
        assert_eq!(
            status.state,
            if abandon {
                OperationState::Cancelled
            } else {
                OperationState::Failed
            }
        );
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(session.core.tcp_pending.available_permits(), 16);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Read,
    Write,
    End,
}
struct RejectingAttachment {
    stage: Stage,
    failure: AttachmentError,
    oversized: bool,
}
impl ApplicationIo for RejectingAttachment {
    fn poll_read(
        &mut self,
        _cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        if self.stage != Stage::Read {
            return Poll::Pending;
        }
        Poll::Ready(if self.oversized {
            Ok(buffer.len() + 1)
        } else {
            Err(self.failure)
        })
    }
    fn poll_write(
        &mut self,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        if self.stage != Stage::Write {
            return Poll::Pending;
        }
        Poll::Ready(if self.oversized {
            Ok(bytes.len() + 1)
        } else {
            Err(self.failure)
        })
    }
    fn poll_send_end(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), AttachmentError>> {
        assert!(self.stage == Stage::End);
        Poll::Ready(Err(self.failure))
    }
}

#[tokio::test]
async fn tcp_service_preserves_fixed_attachment_failures_and_checks_counts() {
    for stage in [Stage::Read, Stage::Write, Stage::End] {
        for failure in [
            AttachmentError::InvalidFrame,
            AttachmentError::LimitExceeded,
            AttachmentError::AttachmentLost,
            AttachmentError::InternalError,
        ] {
            for oversized in [false, true] {
                if oversized && stage == Stage::End {
                    continue;
                }
                let fixture = Fixture::new().await;
                let tcp = TcpFixture::new().await;
                let broker = Broker::new(tcp.configuration(&fixture)).unwrap();
                let session = broker.create_session(tcp_options()).unwrap();
                let Admission::New(pending) = session.open_stream(open()).await.unwrap() else {
                    panic!()
                };
                let Connection::Opened(connected) = pending.connect().await.unwrap() else {
                    panic!()
                };
                let (mut upstream, _) = tcp.listener.accept().await.unwrap();
                match stage {
                    Stage::Read => {}
                    Stage::Write => upstream.write_all(b"x").await.unwrap(),
                    Stage::End => upstream.shutdown().await.unwrap(),
                }
                let terminal = tokio::time::timeout(
                    Duration::from_secs(2),
                    connected.relay(Box::new(RejectingAttachment {
                        stage,
                        failure,
                        oversized,
                    })),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(
                    terminal.cause,
                    if oversized {
                        Cause::InternalError
                    } else {
                        failure.cause()
                    }
                );
                assert_eq!(terminal.operation.state, OperationState::OutcomeUnknown);
                assert_eq!((terminal.sent_bytes, terminal.received_bytes), (0, 0));
                assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
            }
        }
    }
}
