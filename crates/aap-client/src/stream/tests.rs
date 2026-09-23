use super::*;
use crate::tests::{opened, operation, terminal};
use aap_types::OperationState;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn encoded(frames: impl IntoIterator<Item = Frame>) -> Bytes {
    let mut bytes = Vec::new();
    for frame in frames {
        let value = frame.encode().unwrap();
        bytes.extend(value.header);
        bytes.extend(value.payload);
    }
    bytes.into()
}
struct ReplyOnEnd {
    after_end: Bytes,
    header: Vec<u8>,
}
impl AsyncRead for ReplyOnEnd {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.header.len() == 5 {
            let count = buffer.remaining().min(self.after_end.len());
            buffer.put_slice(&self.after_end.split_to(count));
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
impl AsyncWrite for ReplyOnEnd {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.header.extend_from_slice(bytes);
        assert_eq!(self.header, [4, 0, 0, 0, 0]);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("framed end must not shutdown the attachment")
    }
}
struct Empty;
impl ApplicationIo for Empty {
    fn poll_read(
        &mut self,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        Poll::Ready(Ok(0))
    }
    fn poll_write(
        &mut self,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        panic!("no application payload expected")
    }
    fn poll_send_end(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), AttachmentError>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn immediate_terminal_after_written_send_end_is_valid() {
    let request = operation();
    let io = ReplyOnEnd {
        after_end: encoded([Frame::Terminal(terminal(
            &request,
            OperationState::Completed,
        ))]),
        header: Vec::new(),
    };
    let input = encoded([Frame::Opened(opened(&request)), Frame::SendEnd]);
    let owner = Owner::new(Box::new(io), request, input).unwrap();
    let Connection::Opened(connected) = owner.connect().await.unwrap() else {
        panic!()
    };
    let result = connected.relay(Box::new(Empty)).await;
    assert!(
        matches!(result, Ok(value) if value.operation.state==OperationState::Completed),
        "fully written SEND_END must precede acceptance of a ready terminal"
    );
}

struct Silent(Arc<AtomicBool>);
impl Drop for Silent {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl AsyncRead for Silent {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Silent {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
struct QuietApplication {
    dropped: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
}
impl Drop for QuietApplication {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
impl ApplicationIo for QuietApplication {
    fn poll_read(
        &mut self,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
    fn poll_write(
        &mut self,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        Poll::Pending
    }
    fn poll_send_end(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), AttachmentError>> {
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn unpolled_client_owners_expire_and_release_their_application() {
    for phase in 0..3 {
        let request = operation();
        let dropped = Arc::new(AtomicBool::new(false));
        let mut limits = opened(&request);
        limits.idle_timeout_ms = 100;
        limits.remaining_lifetime_ms = 500;
        let prefix = if phase == 0 {
            Bytes::new()
        } else {
            encoded([Frame::Opened(limits)])
        };
        let owner = Owner::new(Box::new(Silent(dropped.clone())), request, prefix).unwrap();
        let abort: Arc<dyn StreamAbort> = owner.shared.clone();
        let application_dropped = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let future: BoxFuture<'static, Result<()>> = if phase == 0 {
            Box::pin(async move { owner.connect().await.map(|_| ()) })
        } else {
            let Connection::Opened(connected) = owner.connect().await.unwrap() else {
                panic!()
            };
            let original = connected.opened().unwrap().remaining_lifetime_ms;
            tokio::time::advance(Duration::from_millis(10)).await;
            assert!(connected.opened().unwrap().remaining_lifetime_ms < original);
            if phase == 1 {
                Box::pin(async move { connected.opened().map(|_| ()) })
            } else {
                let relay = connected.relay(Box::new(QuietApplication {
                    dropped: application_dropped.clone(),
                    reads: reads.clone(),
                }));
                Box::pin(async move { relay.await.map(|_| ()) })
            }
        };
        assert!(!dropped.load(Ordering::SeqCst));
        tokio::time::advance(Duration::from_millis(if phase == 0 { 310001 } else { 101 })).await;
        tokio::time::timeout(Duration::from_secs(1), abort.terminated())
            .await
            .unwrap();
        assert!(
            dropped.load(Ordering::SeqCst),
            "unpolled socket survived expiry"
        );
        assert!(future.await.is_err());
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "unpolled relay read application data"
        );
        if phase == 2 {
            assert!(application_dropped.load(Ordering::SeqCst));
        }
    }
}

#[tokio::test]
async fn drop_and_stop_only_abort_close_every_client_phase() {
    for abort_instead_of_drop in [false, true] {
        for phase in 0..3 {
            let request = operation();
            let dropped = Arc::new(AtomicBool::new(false));
            let prefix = if phase == 0 {
                Bytes::new()
            } else {
                encoded([Frame::Opened(opened(&request))])
            };
            let owner = Owner::new(Box::new(Silent(dropped.clone())), request, prefix).unwrap();
            let abort: Arc<dyn StreamAbort> = owner.shared.clone();
            let application_dropped = Arc::new(AtomicBool::new(false));
            let future: BoxFuture<'static, Result<()>> = if phase == 0 {
                Box::pin(async move { owner.connect().await.map(|_| ()) })
            } else {
                let Connection::Opened(connected) = owner.connect().await.unwrap() else {
                    panic!()
                };
                if phase == 1 {
                    Box::pin(async move { connected.opened().map(|_| ()) })
                } else {
                    let relay = connected.relay(Box::new(QuietApplication {
                        dropped: application_dropped.clone(),
                        reads: Arc::new(AtomicUsize::new(0)),
                    }));
                    Box::pin(async move { relay.await.map(|_| ()) })
                }
            };
            if abort_instead_of_drop {
                abort.abort(AttachmentError::InvalidFrame);
                assert!(
                    dropped.load(Ordering::SeqCst),
                    "abort did not close an unpolled socket"
                );
                assert!(future.await.is_err(), "abort fabricated a daemon outcome");
            } else {
                drop(future);
            }
            assert!(dropped.load(Ordering::SeqCst));
            if phase == 2 {
                assert!(application_dropped.load(Ordering::SeqCst));
            }
            tokio::time::timeout(Duration::from_secs(1), abort.terminated())
                .await
                .unwrap();
            abort.abort(AttachmentError::InternalError);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn ready_opened_cannot_win_an_expired_pending_deadline() {
    let request = operation();
    let owner = Owner::new(
        Box::new(Silent(Arc::new(AtomicBool::new(false)))),
        request.clone(),
        encoded([Frame::Opened(opened(&request))]),
    )
    .unwrap();
    // Do not poll the pending connection until its whole preparation window ends.
    tokio::time::advance(Duration::from_secs(310)).await;
    assert!(
        matches!(owner.connect().await,Err(error) if error.code==ErrorCode::ResultUnavailable && error.request_id.as_deref()==Some(request.request_id.as_str())),
        "expired pending ownership must retain the original ID for status lookup"
    );
}

struct BudgetWire {
    written: Arc<Mutex<Vec<u8>>>,
    remaining: usize,
    reply: Bytes,
}
impl AsyncRead for BudgetWire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        read: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.remaining != 0 {
            return Poll::Pending;
        }
        let count = read.remaining().min(self.reply.len());
        read.put_slice(&self.reply.split_to(count));
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for BudgetWire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.remaining == 0 {
            return Poll::Pending;
        }
        let count = bytes.len().min(self.remaining);
        self.written
            .lock()
            .unwrap()
            .extend_from_slice(&bytes[..count]);
        self.remaining -= count;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("local socket shutdown is not an application end")
    }
}
struct Source(Bytes);
impl ApplicationIo for Source {
    fn poll_read(
        &mut self,
        _: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        let count = buffer.len().min(self.0.len());
        buffer[..count].copy_from_slice(&self.0.split_to(count));
        Poll::Ready(Ok(count))
    }
    fn poll_write(
        &mut self,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        panic!("unexpected inbound bytes")
    }
    fn poll_send_end(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), AttachmentError>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn terminal_counters_cannot_credit_unwritten_payload() {
    for reported in [2, 3] {
        let request = operation();
        let mut outcome = terminal(&request, OperationState::OutcomeUnknown);
        outcome.cause = stream::Cause::AttachmentLost;
        outcome.sent_bytes = reported;
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = BudgetWire {
            written: written.clone(),
            remaining: 7,
            reply: encoded([Frame::Terminal(outcome)]),
        };
        let owner = Owner::new(
            Box::new(io),
            request.clone(),
            encoded([Frame::Opened(opened(&request))]),
        )
        .unwrap();
        let Connection::Opened(connected) = owner.connect().await.unwrap() else {
            panic!()
        };
        let result = connected
            .relay(Box::new(Source(Bytes::from_static(b"abcd"))))
            .await;
        assert_eq!(&*written.lock().unwrap(), b"\x03\0\0\0\x04ab");
        if reported == 2 {
            assert!(
                matches!(result,Ok(value) if value.sent_bytes==2 && value.operation.state==OperationState::OutcomeUnknown)
            );
        } else {
            assert!(
                result.is_err(),
                "terminal credited bytes still in the client queue"
            );
        }
    }
}

#[tokio::test]
async fn client_direction_limit_is_not_reset_by_frame_boundaries() {
    let request = operation();
    let mut metadata = opened(&request);
    metadata.max_data_bytes = 2;
    metadata.send_limit = 4;
    let written = Arc::new(Mutex::new(Vec::new()));
    let io = BudgetWire {
        written: written.clone(),
        remaining: usize::MAX,
        reply: Bytes::new(),
    };
    let owner = Owner::new(Box::new(io), request, encoded([Frame::Opened(metadata)])).unwrap();
    let Connection::Opened(connected) = owner.connect().await.unwrap() else {
        panic!()
    };
    let result = connected
        .relay(Box::new(Source(Bytes::from_static(b"abcde"))))
        .await;
    assert!(matches!(result,Err(error) if error.code==ErrorCode::LimitExceeded));
    assert_eq!(
        &*written.lock().unwrap(),
        b"\x03\0\0\0\x02ab\x03\0\0\0\x02cd"
    );
}

#[tokio::test]
async fn client_callback_bounds_and_local_delivery_failures_are_errors() {
    struct Invalid {
        oversized: bool,
    }
    impl ApplicationIo for Invalid {
        fn poll_read(
            &mut self,
            _: &mut Context<'_>,
            buffer: &mut [u8],
        ) -> Poll<std::result::Result<usize, AttachmentError>> {
            if self.oversized {
                Poll::Ready(Ok(buffer.len() + 1))
            } else {
                Poll::Pending
            }
        }
        fn poll_write(
            &mut self,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<std::result::Result<usize, AttachmentError>> {
            Poll::Ready(Err(AttachmentError::AttachmentLost))
        }
        fn poll_send_end(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), AttachmentError>> {
            Poll::Ready(Ok(()))
        }
    }
    for oversized in [false, true] {
        let request = operation();
        let dropped = Arc::new(AtomicBool::new(false));
        let mut input = vec![Frame::Opened(opened(&request))];
        if !oversized {
            input.push(Frame::Data(Bytes::from_static(b"undelivered")));
        }
        let owner = Owner::new(Box::new(Silent(dropped.clone())), request, encoded(input)).unwrap();
        let Connection::Opened(connected) = owner.connect().await.unwrap() else {
            panic!()
        };
        assert!(
            connected
                .relay(Box::new(Invalid { oversized }))
                .await
                .is_err()
        );
        assert!(dropped.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn completed_client_polls_do_not_retain_the_callers_task() {
    struct Task;
    impl std::task::Wake for Task {
        fn wake(self: Arc<Self>) {}
    }
    for abort_first in [false, true] {
        let request = operation();
        let owner = Owner::new(
            Box::new(Silent(Arc::new(AtomicBool::new(false)))),
            request.clone(),
            encoded([Frame::Opened(opened(&request))]),
        )
        .unwrap();
        let control = owner.shared.clone();
        if abort_first {
            control.abort(AttachmentError::AttachmentLost);
        }
        let task = Arc::new(Task);
        let weak = Arc::downgrade(&task);
        let waker = Waker::from(task);
        let mut future = Box::pin(owner.connect());
        let result = {
            let mut context = Context::from_waker(&waker);
            use std::future::Future;
            let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
                panic!("preloaded opening did not resolve")
            };
            result
        };
        assert_eq!(result.is_err(), abort_first);
        drop(future);
        drop(waker);
        assert!(
            weak.upgrade().is_none(),
            "a completed poll retained the caller task through the stream control handle"
        );
        drop(result);
        drop(control);
    }
}
