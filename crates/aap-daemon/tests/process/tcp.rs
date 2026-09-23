use super::*;
use aap_policy::{TcpLimits, TcpProfile};
use aap_types::stream::service::{Admission, ApplicationIo, AttachmentError, Connection};
use aap_types::stream::{self, Frame, Header};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Application(tokio::io::DuplexStream);
impl ApplicationIo for Application {
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<std::result::Result<usize, AttachmentError>> {
        let mut read = ReadBuf::new(bytes);
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
async fn daemon_tcp_client_delivers_binary_and_cancels_without_reattaching() {
    let mut fixture = Fixture::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    fixture.config.tcp_profiles.push(TcpProfile {
        id: "client-fixture".into(),
        endpoint: address.to_string(),
        addresses: AddressPolicy::Pinned(vec![address.ip()]),
        limits: TcpLimits::default(),
        inspection: stream::Inspection::PlaintextBytes,
        require_approval: false,
        require_observation: true,
    });
    fixture.write();
    let (mut child, ready) = fixture.start().await;
    let (status, attachment) = local(
        fixture.root.join("r").join(ready.control_socket),
        "/aap/operator/v1/session/create",
        json!({"resources":["client-fixture"],"lifetime_seconds":60}),
    )
    .await;
    assert!(status.is_success());
    let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
    let client = aap_client::DaemonSessionClient::new(
        fixture.root.join("r").join(attachment.ingress_socket),
    );
    for action in 0..3 {
        let request = stream::Open {
            request_id: aap_types::ids::random_id(16).unwrap(),
            resource: "client-fixture".into(),
        };
        let Admission::New(pending) = client.open_stream(request.clone()).await.unwrap() else {
            panic!()
        };
        let Connection::Opened(connected) = pending.connect().await.unwrap() else {
            panic!()
        };
        let (mut upstream, _) = listener.accept().await.unwrap();
        let (mut application, local) = tokio::io::duplex(4);
        let relay = connected.relay(Box::new(Application(local)));
        let expected = if action == 0 {
            let upstream = tokio::spawn(async move {
                let mut body = Vec::new();
                upstream.read_to_end(&mut body).await.unwrap();
                assert_eq!(body, b"\0\xffsent");
                upstream.write_all(b"\xff\0reply").await.unwrap();
                upstream.shutdown().await.unwrap();
            });
            let relay = tokio::spawn(relay);
            tokio::time::timeout(Duration::from_secs(3), async {
                application.write_all(b"\0\xffsent").await.unwrap();
                application.shutdown().await.unwrap();
                let mut response = Vec::new();
                application.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"\xff\0reply");
                let terminal = relay.await.unwrap().unwrap();
                assert_eq!(terminal.operation.state, OperationState::Completed);
                assert_eq!((terminal.sent_bytes, terminal.received_bytes), (6, 7));
                upstream.await.unwrap();
            })
            .await
            .unwrap();
            OperationState::Completed
        } else {
            if action == 1 {
                assert_eq!(
                    client
                        .cancel(request.request_id.clone())
                        .await
                        .unwrap()
                        .state,
                    OperationState::OutcomeUnknown
                );
                let terminal = tokio::time::timeout(Duration::from_secs(2), relay)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(terminal.operation.state, OperationState::OutcomeUnknown);
                assert_eq!(terminal.cause, stream::Cause::Cancelled);
                assert_eq!((terminal.sent_bytes, terminal.received_bytes), (0, 0));
            } else {
                // Ownership has transferred, but forwarding has never polled.
                drop(relay);
            }
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), upstream.read(&mut [0]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            OperationState::OutcomeUnknown
        };
        let status = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = client
                    .request_status(request.request_id.clone())
                    .await
                    .unwrap();
                if status.state == expected {
                    break status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status.state, expected);
        let Admission::Existing(duplicate) = client.open_stream(request).await.unwrap() else {
            panic!("duplicate client call reattached")
        };
        assert_eq!(duplicate.state, expected);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    stop(&mut child).await;
}

async fn open_wire(
    path: &std::path::Path,
    operation: &stream::Open,
    extra: &str,
    send_body: bool,
) -> (tokio::net::UnixStream, String) {
    let mut socket = tokio::net::UnixStream::connect(path).await.unwrap();
    let body = serde_json::to_vec(operation).unwrap();
    let head = format!(
        "POST /aap/v1/stream/open HTTP/1.1\r\nHost: aap.local\r\nConnection: upgrade\r\nUpgrade: aap-stream/1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n",
        body.len()
    );
    socket.write_all(head.as_bytes()).await.unwrap();
    if send_body {
        socket.write_all(&body).await.unwrap();
    }
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !response.ends_with(b"\r\n\r\n") {
            response.push(socket.read_u8().await.unwrap());
            assert!(response.len() <= 16 * 1024);
        }
    })
    .await
    .unwrap();
    (socket, String::from_utf8(response).unwrap())
}
async fn next_frame(socket: &mut tokio::net::UnixStream) -> Frame {
    let mut prefix = [0; 5];
    socket.read_exact(&mut prefix).await.unwrap();
    let header = Header::parse(prefix).unwrap();
    let mut payload = vec![0; header.length()];
    socket.read_exact(&mut payload).await.unwrap();
    Frame::decode(header, payload.into()).unwrap()
}

#[tokio::test]
async fn daemon_tcp_upgrade_keeps_framing_local_and_status_authoritative() {
    let mut fixture = Fixture::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    fixture.config.tcp_profiles.push(TcpProfile {
        id: "raw-fixture".into(),
        endpoint: address.to_string(),
        addresses: AddressPolicy::Pinned(vec![address.ip()]),
        limits: TcpLimits::default(),
        inspection: stream::Inspection::PlaintextBytes,
        require_approval: false,
        require_observation: true,
    });
    fixture.write();
    let (mut child, ready) = fixture.start().await;
    let control = fixture.root.join("r").join(ready.control_socket);
    let (status, attachment) = local(
        control.clone(),
        "/aap/operator/v1/session/create",
        json!({"resources":["raw-fixture"],"lifetime_seconds":60}),
    )
    .await;
    assert!(status.is_success());
    let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
    let path = fixture.root.join("r").join(attachment.ingress_socket);
    let request = stream::Open {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "raw-fixture".into(),
    };
    let (mut socket, response) = open_wire(&path, &request, "", true).await;
    assert!(
        response.starts_with("HTTP/1.1 101 "),
        "stream was not upgraded: {response}"
    );
    assert!(!response.to_ascii_lowercase().contains("content-length"));
    assert!(!response.to_ascii_lowercase().contains("transfer-encoding"));
    assert!(
        matches!(next_frame(&mut socket).await, Frame::Opened(value) if value.request_id == request.request_id)
    );
    let (mut upstream, _) = listener.accept().await.unwrap();
    for frame in [Frame::Data(Bytes::from_static(b"\0\xffx")), Frame::SendEnd] {
        let frame = frame.encode().unwrap();
        socket.write_all(&frame.header).await.unwrap();
        socket.write_all(&frame.payload).await.unwrap();
    }
    let mut sent = Vec::new();
    upstream.read_to_end(&mut sent).await.unwrap();
    assert_eq!(sent, b"\0\xffx");
    upstream.write_all(b"reply").await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    let mut ended = false;
    loop {
        match next_frame(&mut socket).await {
            Frame::Data(data) => {
                assert!(!ended);
                reply.extend_from_slice(&data);
            }
            Frame::SendEnd => {
                assert!(!ended);
                ended = true;
            }
            Frame::Terminal(value) => {
                assert!(ended);
                assert_eq!(value.operation.state, OperationState::Completed);
                assert_eq!((value.sent_bytes, value.received_bytes), (3, 5));
                break;
            }
            _ => panic!(),
        }
    }
    assert_eq!(reply, b"reply");
    assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
    let (status, batch) = local(
        fixture.root.join("r").join(ready.observation_socket),
        "/aap/observe/v1/read",
        json!({"limit":128}),
    )
    .await;
    assert!(status.is_success());
    let batch: aap_observe::Batch = serde_json::from_value(batch).unwrap();
    let closes = batch
        .records
        .iter()
        .filter(|record| {
            record.event.protocol == aap_observe::Protocol::Tcp
                && record.event.request_id.as_deref() == Some(request.request_id.as_str())
                && matches!(
                    record.event.data,
                    aap_observe::Data::FlowClose {
                        complete: true,
                        outbound_bytes: 3,
                        inbound_bytes: 5,
                        ..
                    }
                )
        })
        .count();
    assert_eq!(closes, 2, "daemon did not record both completed TCP views");
    let client = aap_client::DaemonSessionClient::new(path.clone());
    assert_eq!(
        client
            .request_status(request.request_id.clone())
            .await
            .unwrap()
            .state,
        OperationState::Completed
    );
    let (_, response) = open_wire(&path, &request, "", true).await;
    assert!(response.starts_with("HTTP/1.1 200 "));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-aap-operation-state: existing")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err(),
        "duplicate opened a second upstream connection"
    );

    for extra in [
        "Authorization: private\r\n",
        "Upgrade: aap-stream/1\r\n",
        "Content-Length: 0\r\n",
        "Cookie: hidden=x\r\n",
    ] {
        let mut rejected = request.clone();
        rejected.request_id = aap_types::ids::random_id(16).unwrap();
        // Invalid headers must be rejected before any body is needed. Writing
        // a body here races the legitimate early rejection/connection close.
        let (_, response) = open_wire(&path, &rejected, extra, false).await;
        assert!(
            response.starts_with("HTTP/1.1 400 "),
            "invalid opening was accepted: {response}"
        );
        assert!(client.request_status(rejected.request_id).await.is_err());
    }
    let (_, response) = open_wire(&control, &request, "", false).await;
    assert!(
        !response.starts_with("HTTP/1.1 101 "),
        "operator endpoint accepted a stream"
    );
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    stop(&mut child).await;
}

#[tokio::test]
async fn tcp_configuration_is_validated_and_cannot_be_used_as_http() {
    let mut fixture = Fixture::new().await;
    let directory = fixture.root.join("c");
    let validate = || {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-auth-proxy"));
        command
            .arg("validate")
            .arg(&directory)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        command
    };
    // Existing schema-1 input need not name TCP resources at all.
    let mut old = serde_json::to_value(&fixture.config).unwrap();
    old.as_object_mut().unwrap().remove("tcp_profiles");
    let old: DaemonConfig = aap_types::json::decode(&serde_json::to_vec(&old).unwrap()).unwrap();
    assert!(old.tcp_profiles.is_empty());
    let raw = TcpProfile {
        id: "raw-fixture".into(),
        endpoint: "raw.test:9000".into(),
        addresses: AddressPolicy::Pinned(vec!["127.0.0.1".parse().unwrap()]),
        limits: TcpLimits::default(),
        inspection: aap_types::stream::Inspection::PlaintextBytes,
        require_approval: false,
        require_observation: true,
    };
    fixture.config.tcp_profiles.push(raw.clone());
    fixture.write();
    assert!(validate().output().await.unwrap().status.success());
    fixture.config.tcp_profiles[0].endpoint =
        format!("fixture.test:{}", fixture.origin.address.port());
    fixture.write();
    assert!(
        !validate().output().await.unwrap().status.success(),
        "daemon validation admitted raw access to inspected provider"
    );
    fixture.config.tcp_profiles[0] = raw;
    fixture.write();
    let (mut child, ready) = fixture.start().await;
    let (status, attachment) = local(
        fixture.root.join("r").join(ready.control_socket),
        "/aap/operator/v1/session/create",
        json!({"resources":["raw-fixture"],"lifetime_seconds":60}),
    )
    .await;
    assert!(status.is_success());
    let attachment: SessionAttachment = serde_json::from_value(attachment).unwrap();
    let client = aap_client::DaemonSessionClient::new(
        fixture.root.join("r").join(attachment.ingress_socket),
    );
    let mut request = fixture.request();
    request.resource = "raw-fixture".into();
    assert!(client.execute(request).await.is_err());
    assert!(fixture.origin.requests.lock().unwrap().is_empty());
    stop(&mut child).await;
}
