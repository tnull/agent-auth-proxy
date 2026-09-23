use super::{boundary::Boundary, *};
use aap_policy::{TcpLimits, TcpProfile};
use aap_types::stream;
use std::{
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SEND: &[u8] = b"\0\xffconfined-stream";
const REPLY: &[u8] = b"\xff\0private-peer-reply";

struct Peer {
    address: SocketAddr,
    accepts: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Peer {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let count = accepts.clone();
        let requests = Arc::new(Mutex::new(vec![]));
        let received = requests.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = connections.join_next(), if !connections.is_empty() => {result.unwrap().unwrap();}
                    accepted = listener.accept() => {
                        let (mut socket, _) = accepted.unwrap();
                        assert!(count.fetch_add(1, Ordering::SeqCst) < 32);
                        let received = received.clone();
                        connections.spawn(async move {
                            tokio::time::timeout(Duration::from_secs(5), async {
                                let mut bytes = vec![];
                                (&mut socket).take(16*1024 + 1).read_to_end(&mut bytes).await.unwrap();
                                assert!(bytes.len() <= 16*1024);
                                let positive = bytes == b"probe";
                                if !positive { assert_eq!(bytes, SEND); }
                                received.lock().unwrap().push(bytes);
                                if !positive { socket.write_all(REPLY).await.unwrap(); }
                                socket.shutdown().await.unwrap();
                            }).await.unwrap();
                        });
                    }
                }
            }
        });
        Self {
            address,
            accepts,
            requests,
            task,
        }
    }
    async fn baseline(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.requests.lock().unwrap().len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            self.requests
                .lock()
                .unwrap()
                .iter()
                .all(|bytes| bytes == b"probe")
        );
        self.check(2);
    }
    fn check(&self, expected: usize) {
        assert!(!self.task.is_finished(), "plaintext fixture failed");
        assert_eq!(
            self.accepts.load(Ordering::SeqCst),
            expected,
            "unexpected direct or repeated TCP connection"
        );
        assert_eq!(self.requests.lock().unwrap().len(), expected);
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn open() -> stream::Open {
    stream::Open {
        request_id: aap_types::ids::random_id(16).unwrap(),
        resource: "confined-raw".into(),
    }
}
fn action(open: &stream::Open) -> Value {
    json!({"kind":"stream","open":open,"send":SEND})
}
fn completed(result: &Value, request: &stream::Open) {
    assert_eq!(result["opened"]["request_id"], request.request_id);
    assert_eq!(result["received"], json!(REPLY));
    assert_eq!(result["received_end"], true);
    assert_eq!(
        result["terminal"]["operation"]["request_id"],
        request.request_id
    );
    assert_eq!(
        result["terminal"]["operation"]["state"],
        json!(OperationState::Completed)
    );
    assert_eq!(
        result["terminal"]["cause"],
        json!(stream::Cause::OrderlyEnd)
    );
    assert_eq!(result["terminal"]["sent_bytes"], SEND.len());
    assert_eq!(result["terminal"]["received_bytes"], REPLY.len());
}

#[tokio::test]
#[ignore = "requires the explicit Linux confinement setup in docs/confinement.md"]
async fn confined_tcp_client_preserves_binary_half_close_and_session_limits() {
    let _exclusive = LAUNCH_TEST_LOCK.lock().await;
    let peer = Peer::new().await;
    let mut fixture = Fixture::new().await;
    fixture.config.tcp_profiles.push(TcpProfile {
        id: "confined-raw".into(),
        endpoint: peer.address.to_string(),
        addresses: AddressPolicy::Pinned(vec![peer.address.ip()]),
        limits: TcpLimits::default(),
        inspection: stream::Inspection::PlaintextBytes,
        require_approval: false,
        require_observation: true,
    });
    fixture.write();
    let (mut daemon, ready) = fixture.start().await;
    let boundary = Boundary::new(
        &fixture,
        &daemon,
        &ready,
        json!({"resources":["confined-raw"],"lifetime_seconds":120}),
        &[peer.address],
    )
    .await;
    peer.baseline().await;
    let mut processes = [boundary.spawn(0).await, boundary.spawn(1).await];
    let request = open();
    completed(
        &boundary
            .action(&mut processes[0], 0, action(&request))
            .await,
        &request,
    );
    peer.check(3);
    let duplicate = boundary
        .action(&mut processes[0], 0, action(&request))
        .await;
    assert_eq!(
        duplicate["existing"]["state"],
        json!(OperationState::Completed)
    );
    assert!(duplicate.get("opened").is_none());
    peer.check(3);
    // Identical public operation IDs do not select another session or replay
    // its result; the second attachment has its own admitted stream.
    completed(
        &boundary
            .action(&mut processes[1], 1, action(&request))
            .await,
        &request,
    );
    peer.check(4);
    let (status, batch) = local(
        boundary.observer.clone(),
        "/aap/observe/v1/read",
        json!({"limit":256}),
    )
    .await;
    assert!(status.is_success());
    let batch: aap_observe::Batch = serde_json::from_value(batch).unwrap();
    for session in &boundary.sessions {
        let events: Vec<_> = batch
            .records
            .iter()
            .filter(|record| {
                record.event.session_id == session.session_id
                    && record.event.request_id.as_deref() == Some(&request.request_id)
            })
            .map(|record| &record.event)
            .collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event.data,
                    aap_observe::Data::FlowClose { complete: true, .. }
                ))
                .count(),
            2
        );
        for view in [aap_observe::View::Agent, aap_observe::View::Upstream] {
            for (direction, expected) in [
                (aap_observe::Direction::Outbound, SEND),
                (aap_observe::Direction::Inbound, REPLY),
            ] {
                let mut bytes = vec![];
                for event in &events {
                    if event.view == view
                        && event.direction == direction
                        && let aap_observe::Data::ContentChunk { body_base64, .. } = &event.data
                    {
                        bytes.extend(STANDARD.decode(body_base64).unwrap());
                    }
                }
                assert_eq!(bytes, expected);
            }
        }
    }
    assert!(
        local(
            boundary.control.clone(),
            "/aap/operator/v1/session/revoke",
            json!({"session_id":boundary.sessions[0].session_id})
        )
        .await
        .0
        .is_success()
    );
    let denied = boundary
        .action_result(&mut processes[0], 0, action(&open()))
        .await;
    assert!(!denied["error"].is_null());
    assert!(denied["value"].is_null());
    peer.check(4);
    let still_live = open();
    completed(
        &boundary
            .action(&mut processes[1], 1, action(&still_live))
            .await,
        &still_live,
    );
    peer.check(5);
    let collector = boundary.tiny_collector(1).await;
    let denied = boundary.action(&mut processes[1], 1, action(&open())).await;
    assert_eq!(
        denied["terminal"]["cause"],
        json!(stream::Cause::ObservationUnavailable)
    );
    assert_eq!(denied["terminal"]["sent_bytes"], 0);
    assert!(denied.get("opened").is_none());
    peer.check(5);
    boundary.remove_collector(collector).await;
    let resumed = open();
    completed(
        &boundary
            .action(&mut processes[1], 1, action(&resumed))
            .await,
        &resumed,
    );
    peer.check(6);
    let mut approval = boundary.approval_process(&fixture, &["confined-raw"]).await;
    let denied = boundary.action(&mut approval, 0, action(&open())).await;
    assert_eq!(
        denied["terminal"]["cause"],
        json!(stream::Cause::InteractionUnavailable)
    );
    assert_eq!(denied["terminal"]["sent_bytes"], 0);
    assert!(denied.get("opened").is_none());
    peer.check(6);
    approval.finish().await;
    for process in processes {
        process.finish().await;
    }
    assert!(
        fixture.origin.requests.lock().unwrap().is_empty(),
        "raw stream reached the inspected provider"
    );
    boundary.assert_no_bypass();
    peer.check(6);
    stop(&mut daemon).await;
}
