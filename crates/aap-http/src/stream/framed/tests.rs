use super::*;
use aap_types::{
    OperationState, OperationStatus,
    stream::{Cause, Frame, Header, Inspection, Observation},
};
use bytes::Bytes;
use std::{
    future::poll_fn,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

fn opening() -> (stream::Open, stream::Opened) {
    let request = stream::Open {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "raw".into(),
    };
    let opened = stream::Opened {
        request_id: request.request_id.clone(),
        resource: request.resource.clone(),
        max_data_bytes: stream::MAX_DATA_BYTES as u32,
        send_limit: stream::MAX_DIRECTION_BYTES,
        receive_limit: stream::MAX_DIRECTION_BYTES,
        idle_timeout_ms: 60_000,
        remaining_lifetime_ms: 600_000,
        inspection: Inspection::PlaintextBytes,
        observation: Observation::Required,
    };
    (request, opened)
}
fn terminal(request: &stream::Open, cause: Cause, sent: u64, received: u64) -> stream::Terminal {
    stream::Terminal {
        operation: OperationStatus {
            request_id: request.request_id.clone(),
            state: if cause == Cause::OrderlyEnd {
                OperationState::Completed
            } else {
                OperationState::OutcomeUnknown
            },
            status: None,
        },
        cause,
        sent_bytes: sent,
        received_bytes: received,
    }
}
fn encoded(frame: Frame) -> Vec<u8> {
    let encoded = frame.encode().unwrap();
    [encoded.header.as_slice(), &encoded.payload].concat()
}
async fn next(peer: &mut tokio::io::DuplexStream) -> Frame {
    let mut header = [0; 5];
    peer.read_exact(&mut header).await.unwrap();
    let header = Header::parse(header).unwrap();
    let mut payload = vec![0; header.length()];
    peer.read_exact(&mut payload).await.unwrap();
    Frame::decode(header, payload.into()).unwrap()
}
async fn read(
    app: &mut dyn ApplicationIo,
    bytes: &mut [u8],
) -> std::result::Result<usize, AttachmentError> {
    poll_fn(|cx| app.poll_read(cx, bytes)).await
}
async fn write(
    app: &mut dyn ApplicationIo,
    mut bytes: &[u8],
) -> std::result::Result<(), AttachmentError> {
    while !bytes.is_empty() {
        let count = poll_fn(|cx| app.poll_write(cx, bytes)).await?;
        assert!(count > 0);
        bytes = &bytes[count..];
    }
    Ok(())
}
async fn end(app: &mut dyn ApplicationIo) -> std::result::Result<(), AttachmentError> {
    poll_fn(|cx| app.poll_send_end(cx)).await
}

#[tokio::test]
async fn framed_binary_split_input_and_both_half_close_orders() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for daemon_first in [false, true] {
            for split_bytes in [false, true] {
                let (request, opened) = opening();
                let (mut peer, local) = tokio::io::duplex(128);
                let (control, mut app) = channel(Box::new(local), request.clone(), opened).unwrap();
                let mut input = encoded(Frame::Data(Bytes::from_static(b"request\0\xff")));
                input.extend(encoded(Frame::SendEnd));
                let peer = tokio::spawn(async move {
                    if daemon_first {
                        assert!(matches!(next(&mut peer).await, Frame::Data(data) if data == b"reply\0\xfe".as_slice()));
                        assert!(matches!(next(&mut peer).await, Frame::SendEnd));
                    }
                    if split_bytes {
                        for byte in input { peer.write_all(&[byte]).await.unwrap(); tokio::task::yield_now().await; }
                    } else { peer.write_all(&input).await.unwrap(); }
                    if !daemon_first {
                        assert!(matches!(next(&mut peer).await, Frame::Data(data) if data == b"reply\0\xfe".as_slice()));
                        assert!(matches!(next(&mut peer).await, Frame::SendEnd));
                    }
                    assert!(matches!(next(&mut peer).await, Frame::Terminal(value) if value.cause == Cause::OrderlyEnd && value.sent_bytes == 9 && value.received_bytes == 7));
                    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                });
                if daemon_first { write(&mut *app, b"reply\0\xfe").await.unwrap(); end(&mut *app).await.unwrap(); }
                let mut observed = Vec::new();
                loop { let mut buffer = [0;2]; let count = read(&mut *app, &mut buffer).await.unwrap(); if count == 0 {break;} observed.extend_from_slice(&buffer[..count]); }
                assert_eq!(observed, b"request\0\xff");
                if !daemon_first { write(&mut *app, b"reply\0\xfe").await.unwrap(); end(&mut *app).await.unwrap(); }
                drop(app);
                control.finish(&terminal(&request, Cause::OrderlyEnd, 9, 7)).await.unwrap();
                peer.await.unwrap();
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn framed_invalid_headers_and_attachment_eof_never_become_send_end() {
    for (input, expected) in [
        (vec![99, 0, 0, 0, 0], AttachmentError::InvalidFrame),
        (vec![3, 0, 0, 0, 0], AttachmentError::InvalidFrame),
        (vec![4, 0, 0, 0, 1], AttachmentError::InvalidFrame),
        (vec![1, 0, 0, 0, 1], AttachmentError::InvalidFrame),
        (vec![2, 0, 0, 0, 1], AttachmentError::InvalidFrame),
        (vec![5, 0, 0, 0, 1], AttachmentError::InvalidFrame),
        (vec![3, 255, 255, 255, 255], AttachmentError::LimitExceeded),
        (vec![3, 0, 0], AttachmentError::AttachmentLost),
        (vec![3, 0, 0, 0, 2, 65], AttachmentError::AttachmentLost),
        (vec![], AttachmentError::AttachmentLost),
    ] {
        let (request, opened) = opening();
        let (mut peer, local) = tokio::io::duplex(128);
        let (_control, mut app) = channel(Box::new(local), request, opened).unwrap();
        peer.write_all(&input).await.unwrap();
        peer.shutdown().await.unwrap();
        assert_eq!(read(&mut *app, &mut [0; 16]).await.unwrap_err(), expected);
    }
}

#[tokio::test]
async fn framed_post_end_input_is_detected_even_without_another_application_read() {
    for coalesced in [false, true] {
        for raw_eof in [false, true] {
            let (request, opened) = opening();
            let (mut peer, local) = tokio::io::duplex(128);
            let (control, mut app) = channel(Box::new(local), request, opened).unwrap();
            let mut input = encoded(Frame::SendEnd);
            if coalesced && !raw_eof {
                input.extend(encoded(Frame::SendEnd));
            }
            peer.write_all(&input).await.unwrap();
            if coalesced && !raw_eof {
                assert_eq!(
                    read(&mut *app, &mut [0]).await.unwrap_err(),
                    AttachmentError::InvalidFrame
                );
                continue;
            }
            assert_eq!(read(&mut *app, &mut [0]).await.unwrap(), 0);
            if raw_eof {
                peer.shutdown().await.unwrap();
            } else {
                peer.write_all(&encoded(Frame::Data(Bytes::from_static(b"x"))))
                    .await
                    .unwrap();
            }
            let fault = poll_fn(|cx| match control.fault(cx) {
                Some(error) => Poll::Ready(error),
                None => Poll::Pending,
            })
            .await;
            assert_eq!(
                fault,
                if raw_eof {
                    AttachmentError::AttachmentLost
                } else {
                    AttachmentError::InvalidFrame
                }
            );
        }
    }
}

#[tokio::test]
async fn framed_narrowed_budgets_bound_input_and_output_before_acceptance() {
    let (request, mut opened) = opening();
    opened.max_data_bytes = 2;
    opened.send_limit = 3;
    opened.receive_limit = 3;
    let (mut peer, local) = tokio::io::duplex(128);
    let (_control, mut app) = channel(Box::new(local), request, opened).unwrap();
    assert_eq!(poll_fn(|cx| app.poll_write(cx, b"abcd")).await.unwrap(), 2);
    assert!(matches!(next(&mut peer).await, Frame::Data(value) if value == b"ab".as_slice()));
    assert_eq!(
        poll_fn(|cx| app.poll_write(cx, b"cd")).await.unwrap_err(),
        AttachmentError::LimitExceeded
    );

    let (request, mut opened) = opening();
    opened.max_data_bytes = 2;
    let (mut peer, local) = tokio::io::duplex(128);
    let (_control, mut app) = channel(Box::new(local), request, opened).unwrap();
    peer.write_all(&[3, 0, 0, 0, 3]).await.unwrap();
    assert_eq!(
        read(&mut *app, &mut [0; 8]).await.unwrap_err(),
        AttachmentError::LimitExceeded
    );
}

struct BudgetIo {
    budget: Arc<AtomicUsize>,
    written: Arc<Mutex<Vec<u8>>>,
}
impl AsyncRead for BudgetIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for BudgetIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let count = bytes.len().min(self.budget.load(Ordering::SeqCst));
        if count == 0 {
            return Poll::Pending;
        }
        self.budget.fetch_sub(count, Ordering::SeqCst);
        self.written
            .lock()
            .unwrap()
            .extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn framed_partial_data_counts_actual_prefix_and_forbids_terminal_insertion() {
    for budget in [0, 1, 5, 7] {
        let available = Arc::new(AtomicUsize::new(budget));
        let written = Arc::new(Mutex::new(vec![]));
        let (request, opened) = opening();
        let (control, mut app) = channel(
            Box::new(BudgetIo {
                budget: available.clone(),
                written: written.clone(),
            }),
            request.clone(),
            opened,
        )
        .unwrap();
        let count = poll_fn(|cx| {
            Poll::Ready(match app.poll_write(cx, b"abcd") {
                Poll::Pending => 0,
                Poll::Ready(result) => result.unwrap(),
            })
        })
        .await;
        assert_eq!(count, budget.saturating_sub(5));
        drop(app);
        available.store(16 * 1024, Ordering::SeqCst);
        let result = control
            .finish(&terminal(&request, Cause::Cancelled, 0, count as u64))
            .await;
        if budget == 0 {
            result.unwrap();
            assert_eq!(written.lock().unwrap()[0], 5);
        } else {
            assert!(
                result.is_err(),
                "inserted a terminal inside unfinished DATA"
            );
            assert_eq!(written.lock().unwrap().len(), budget);
        }
    }
}

#[tokio::test]
async fn framed_terminal_delivery_is_bounded_even_without_socket_wakeups() {
    let (request, opened) = opening();
    let (control, app) = channel(
        Box::new(BudgetIo {
            budget: Arc::new(AtomicUsize::new(0)),
            written: Arc::new(Mutex::new(vec![])),
        }),
        request.clone(),
        opened,
    )
    .unwrap();
    drop(app);
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    assert!(
        control
            .finish(&terminal(&request, Cause::Cancelled, 0, 0))
            .await
            .is_err()
    );
    assert!(tokio::time::Instant::now() - start <= std::time::Duration::from_millis(2001));
}

#[tokio::test]
async fn framed_frame_count_ceiling_and_retired_payload_are_bounded() {
    let (request, opened) = opening();
    let (mut peer, local) = tokio::io::duplex(64 * 1024);
    let (control, mut app) = channel(Box::new(local), request, opened).unwrap();
    let writer = tokio::spawn(async move {
        for _ in 0..=stream::MAX_DATA_FRAMES {
            peer.write_all(&[3, 0, 0, 0, 1, 65]).await.unwrap();
        }
        peer
    });
    for _ in 0..stream::MAX_DATA_FRAMES {
        assert_eq!(read(&mut *app, &mut [0; 16]).await.unwrap(), 1);
    }
    assert_eq!(
        read(&mut *app, &mut [0; 16]).await.unwrap_err(),
        AttachmentError::LimitExceeded
    );
    let _peer = writer.await.unwrap();
    drop(app);
    drop(control);

    let (request, opened) = opening();
    let (mut peer, local) = tokio::io::duplex(64 * 1024);
    let (control, mut app) = channel(Box::new(local), request, opened).unwrap();
    peer.write_all(&encoded(Frame::Data(Bytes::from(
        vec![65; stream::MAX_DATA_BYTES],
    ))))
    .await
    .unwrap();
    assert_eq!(read(&mut *app, &mut [0]).await.unwrap(), 1);
    assert_eq!(
        control.0.lock().unwrap().pending.len(),
        stream::MAX_DATA_BYTES - 1
    );
    drop(app);
    let state = control.0.lock().unwrap();
    assert!(state.retired && state.pending.is_empty() && state.scratch.is_empty());
}
