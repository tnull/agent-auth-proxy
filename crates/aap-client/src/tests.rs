use super::*;
use aap_types::stream::{
    self, Frame, Header,
    service::{Admission, ApplicationIo, AttachmentError, Connection},
};
use std::{os::unix::fs::DirBuilderExt, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{UnixListener, UnixStream},
};

struct Fixture {
    root: PathBuf,
    listener: UnixListener,
    client: DaemonSessionClient,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "aap-client-{}",
            aap_types::ids::random_id(16).unwrap()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let path = root.join("session.sock");
        Self {
            listener: UnixListener::bind(&path).unwrap(),
            client: DaemonSessionClient::new(path),
            root,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
pub(crate) fn operation() -> stream::Open {
    stream::Open {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "raw".into(),
    }
}
pub(crate) fn opened(request: &stream::Open) -> stream::Opened {
    stream::Opened {
        request_id: request.request_id.clone(),
        resource: request.resource.clone(),
        max_data_bytes: 32768,
        send_limit: 1024,
        receive_limit: 1024,
        idle_timeout_ms: 60000,
        remaining_lifetime_ms: 600000,
        inspection: stream::Inspection::PlaintextBytes,
        observation: stream::Observation::Required,
    }
}
pub(crate) fn terminal(request: &stream::Open, state: OperationState) -> stream::Terminal {
    stream::Terminal {
        operation: OperationStatus {
            request_id: request.request_id.clone(),
            state,
            status: None,
        },
        cause: if state == OperationState::Completed {
            stream::Cause::OrderlyEnd
        } else {
            stream::Cause::ApprovalDenied
        },
        sent_bytes: 0,
        received_bytes: 0,
    }
}
const UPGRADE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: aap-stream/1\r\n\r\n";
fn append(bytes: &mut Vec<u8>, frame: Frame) {
    let encoded = frame.encode().unwrap();
    bytes.extend_from_slice(&encoded.header);
    bytes.extend_from_slice(&encoded.payload);
}
async fn accept(fixture: &Fixture, expected: &stream::Open) -> UnixStream {
    let (mut peer, _) = fixture.listener.accept().await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(peer.read_u8().await.unwrap());
        assert!(header.len() <= 16 * 1024);
    }
    let header = String::from_utf8(header).unwrap();
    assert!(header.starts_with("POST /aap/v1/stream/open HTTP/1.1\r\n"));
    let lower = header.to_ascii_lowercase();
    for required in [
        "host: aap.local\r\n",
        "connection: upgrade\r\n",
        "upgrade: aap-stream/1\r\n",
        "content-type: application/json\r\n",
    ] {
        assert!(lower.contains(required));
    }
    assert!(!lower.contains("authorization:") && !lower.contains("cookie:"));
    let length = lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!(length <= 16 * 1024);
    let mut body = vec![0; length];
    peer.read_exact(&mut body).await.unwrap();
    assert_eq!(&stream::Open::decode(&body).unwrap(), expected);
    peer
}
async fn next(peer: &mut UnixStream) -> Frame {
    let mut bytes = [0; 5];
    peer.read_exact(&mut bytes).await.unwrap();
    let header = Header::parse(bytes).unwrap();
    let mut body = vec![0; header.length()];
    peer.read_exact(&mut body).await.unwrap();
    Frame::decode(header, body.into()).unwrap()
}
async fn write_frame(peer: &mut UnixStream, frame: Frame) {
    let encoded = frame.encode().unwrap();
    peer.write_all(&encoded.header).await.unwrap();
    peer.write_all(&encoded.payload).await.unwrap();
}
struct Application(tokio::io::DuplexStream);
impl ApplicationIo for Application {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        let mut read = ReadBuf::new(buffer);
        match Pin::new(&mut self.0).poll_read(cx, &mut read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read.filled().len())),
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
async fn stream_client_preserves_binary_half_close_and_terminal_outcome() {
    for peer_ends_first in [false, true] {
        let fixture = Arc::new(Fixture::new());
        let request = operation();
        let server_fixture = fixture.clone();
        let server_request = request.clone();
        let server = tokio::spawn(async move {
            let mut peer = accept(&server_fixture, &server_request).await;
            let mut response = UPGRADE.to_vec();
            append(&mut response, Frame::Opened(opened(&server_request)));
            if peer_ends_first {
                append(
                    &mut response,
                    Frame::Data(Bytes::from_static(b"\xff\0reply")),
                );
                append(&mut response, Frame::SendEnd);
            }
            peer.write_all(&response).await.unwrap();
            let mut payload = Vec::new();
            loop {
                match next(&mut peer).await {
                    Frame::Data(bytes) => payload.extend_from_slice(&bytes),
                    Frame::SendEnd => break,
                    _ => panic!("client sent a daemon-only control"),
                }
            }
            assert_eq!(payload, b"\0\xffsent");
            if !peer_ends_first {
                write_frame(&mut peer, Frame::Data(Bytes::from_static(b"\xff\0reply"))).await;
                write_frame(&mut peer, Frame::SendEnd).await;
            }
            let mut done = terminal(&server_request, OperationState::Completed);
            done.sent_bytes = 6;
            done.received_bytes = 7;
            write_frame(&mut peer, Frame::Terminal(done)).await;
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        });
        let Admission::New(pending) = fixture.client.open_stream(request).await.unwrap() else {
            panic!("new open did not return an attachment")
        };
        let Connection::Opened(connected) = pending.connect().await.unwrap() else {
            panic!("peer did not open")
        };
        assert_eq!(connected.opened().unwrap().resource, "raw");
        let (mut application, local) = tokio::io::duplex(4);
        let relay = tokio::spawn(connected.relay(Box::new(Application(local))));
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut read, mut write) = tokio::io::split(&mut application);
            let sending = async {
                write.write_all(b"\0\xffsent").await.unwrap();
                write.shutdown().await.unwrap();
            };
            let receiving = async {
                let mut output = Vec::new();
                read.read_to_end(&mut output).await.unwrap();
                assert_eq!(output, b"\xff\0reply");
            };
            tokio::join!(sending, receiving);
            let done = relay.await.unwrap().unwrap();
            assert_eq!(done.operation.state, OperationState::Completed);
            assert_eq!((done.sent_bytes, done.received_bytes), (6, 7));
            server.await.unwrap();
        })
        .await
        .expect("duplex client stalled");
    }
}

#[tokio::test]
async fn stream_client_distinguishes_existing_and_pre_open_terminal() {
    for existing in [false, true] {
        let fixture = Arc::new(Fixture::new());
        let request = operation();
        let server_fixture = fixture.clone();
        let server_request = request.clone();
        let server = tokio::spawn(async move {
            let mut peer = accept(&server_fixture, &server_request).await;
            let status = terminal(&server_request, OperationState::Denied);
            let response = if existing {
                let body = serde_json::to_vec(&status.operation).unwrap();
                let mut bytes = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-aap-operation-state: existing\r\n\r\n", body.len()).into_bytes();
                bytes.extend(body);
                bytes
            } else {
                let mut bytes = UPGRADE.to_vec();
                append(
                    &mut bytes,
                    Frame::Pending(stream::Pending {
                        request_id: server_request.request_id.clone(),
                        expires_in_ms: 1000,
                    }),
                );
                append(&mut bytes, Frame::Terminal(status));
                bytes
            };
            // Exercise every HTTP/control header and payload boundary.
            for byte in response {
                peer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        match fixture.client.open_stream(request).await.unwrap() {
            Admission::Existing(status) => {
                assert!(existing);
                assert_eq!(status.state, OperationState::Denied);
            }
            Admission::New(pending) => {
                assert!(!existing);
                let Connection::Terminal(status) = pending.connect().await.unwrap() else {
                    panic!("denied connection opened")
                };
                assert_eq!(status.operation.state, OperationState::Denied);
            }
        }
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), fixture.listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn stream_client_never_succeeds_from_eof_or_impossible_completion() {
    for impossible_terminal in [false, true] {
        let fixture = Arc::new(Fixture::new());
        let request = operation();
        let server_fixture = fixture.clone();
        let server_request = request.clone();
        let server = tokio::spawn(async move {
            let mut peer = accept(&server_fixture, &server_request).await;
            let mut response = UPGRADE.to_vec();
            append(&mut response, Frame::Opened(opened(&server_request)));
            if impossible_terminal {
                append(
                    &mut response,
                    Frame::Terminal(terminal(&server_request, OperationState::Completed)),
                );
            } else {
                append(&mut response, Frame::SendEnd);
            }
            peer.write_all(&response).await.unwrap();
            // No complete valid terminal; closing must never imply success.
        });
        let Admission::New(pending) = fixture.client.open_stream(request).await.unwrap() else {
            panic!()
        };
        let Connection::Opened(connected) = pending.connect().await.unwrap() else {
            panic!()
        };
        let (_application, local) = tokio::io::duplex(4);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                connected.relay(Box::new(Application(local)))
            )
            .await
            .unwrap()
            .is_err()
        );
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), fixture.listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn stream_opening_rejects_ambiguous_responses_without_retry() {
    let valid = String::from_utf8(UPGRADE.to_vec()).unwrap();
    let safe_error = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 24\r\nx-aap-error: 1\r\n\r\n{\"code\":\"policy_denied\"}".to_vec();
    let mixed_case_error = String::from_utf8(safe_error.clone())
        .unwrap()
        .replace("Connection: close", "cOnNeCtIoN: ClOsE")
        .into_bytes();
    let mut cases = vec![
        (safe_error, ErrorCode::PolicyDenied),
        (mixed_case_error, ErrorCode::PolicyDenied),
    ];
    for value in [
        valid.replace("HTTP/1.1", "HTTP/1.0"),
        valid.replace("101 Switching Protocols", "302 Found"),
        valid.replace("Connection: upgrade", "Connection: upgrade, close"),
        valid.replace("Connection: upgrade", "Connection: upgrade\r\nconnection: upgrade"),
        valid.replace("Upgrade: aap-stream/1", "Upgrade: aap-stream/2"),
        valid.replace("Upgrade: aap-stream/1", "Upgrade: aap-stream/1\r\nUpgrade: aap-stream/1"),
        valid.replace("\r\n\r\n", "\r\nContent-Length: 0\r\n\r\n"),
        valid.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n"),
        valid.replace("\r\n\r\n", "\r\nSet-Cookie: hidden=bad\r\n\r\n"),
        valid.replace("\r\n\r\n", "\r\nx-aap-error: 1\r\n\r\n"),
        valid.replace("\r\n", "\n"),
        "HTTP/1.1 100 Continue\r\n\r\n".to_owned()+&valid,
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\nx-aap-operation-state: existing\r\n\r\n{}".into(),
    ] {cases.push((value.into_bytes(),ErrorCode::ResultUnavailable));}
    for (response, code) in cases {
        let fixture = Arc::new(Fixture::new());
        let request = operation();
        let server_fixture = fixture.clone();
        let server_request = request.clone();
        let server = tokio::spawn(async move {
            let mut peer = accept(&server_fixture, &server_request).await;
            peer.write_all(&response).await.unwrap();
        });
        let result = fixture.client.open_stream(request.clone()).await;
        assert!(
            matches!(result,Err(error) if error.code==code && error.request_id.as_deref()==Some(&request.request_id)),
            "incorrect opening failure classification"
        );
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), fixture.listener.accept())
                .await
                .is_err(),
            "client retried an invalid response"
        );
    }
}

#[tokio::test]
async fn stream_opening_checks_existing_status_and_control_identity() {
    for kind in 0..6 {
        let fixture = Arc::new(Fixture::new());
        let request = operation();
        let server_fixture = fixture.clone();
        let server_request = request.clone();
        let server = tokio::spawn(async move {
            let mut peer = accept(&server_fixture, &server_request).await;
            let response = if kind < 4 {
                let mut status = terminal(&server_request, OperationState::Completed).operation;
                if kind == 0 {
                    status.request_id = operation().request_id;
                }
                let mut body = serde_json::to_value(status).unwrap();
                if kind == 1 {
                    body["unexpected"] = true.into();
                }
                if kind == 2 {
                    body.as_object_mut().unwrap().remove("status");
                }
                let body = serde_json::to_vec(&body).unwrap();
                let status = if kind == 3 { 202 } else { 200 };
                let mut response = format!("HTTP/1.1 {status} Status\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-aap-operation-state: existing\r\n\r\n",body.len()).into_bytes();
                response.extend(body);
                response
            } else {
                let mut response = UPGRADE.to_vec();
                let mut metadata = opened(&server_request);
                if kind == 4 {
                    metadata.request_id = operation().request_id;
                } else {
                    metadata.resource = "another".into();
                }
                append(&mut response, Frame::Opened(metadata));
                response
            };
            peer.write_all(&response).await.unwrap();
        });
        let result = fixture.client.open_stream(request).await;
        if kind < 4 {
            assert!(result.is_err(), "invalid existing result was accepted");
        } else {
            let Admission::New(pending) = result.unwrap() else {
                panic!()
            };
            assert!(
                pending.connect().await.is_err(),
                "foreign control created a connected handle"
            );
        }
        server.await.unwrap();
    }
}
