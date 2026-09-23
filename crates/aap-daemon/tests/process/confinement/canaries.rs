use std::{
    net::SocketAddr,
    os::{linux::net::SocketAddrExt, unix::net},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub struct Canaries {
    pub tcp: Vec<SocketAddr>,
    pub udp: Vec<SocketAddr>,
    pub unix: PathBuf,
    pub abstract_unix: String,
    counts: Vec<Arc<AtomicUsize>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Canaries {
    pub async fn new(root: &Path) -> Self {
        let mut this = Self {
            tcp: vec![],
            udp: vec![],
            unix: root.join("host.sock"),
            abstract_unix: format!("aap-fixture-{}", aap_types::ids::random_id(16).unwrap()),
            counts: vec![],
            tasks: vec![],
        };
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .expect("IPv4/IPv6 is a required gate");
            this.tcp.push(listener.local_addr().unwrap());
            let count = this.counter();
            this.tasks.push(tokio::spawn(async move {
                // Keep the deliberately inherited connection usable until
                // teardown instead of passing an already-closed authority.
                let mut connections = Vec::new();
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    assert!(connections.len() < 32, "unexpected canary connection flood");
                    connections.push(stream);
                }
            }));
            let socket = tokio::net::UdpSocket::bind(address).await.unwrap();
            this.udp.push(socket.local_addr().unwrap());
            let count = this.counter();
            this.tasks.push(tokio::spawn(async move {
                loop {
                    let (_, peer) = socket.recv_from(&mut [0; 64]).await.unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    socket.send_to(b"received", peer).await.unwrap();
                }
            }));
        }
        let filesystem = net::UnixListener::bind(&this.unix).unwrap();
        let abstract_socket = net::UnixListener::bind_addr(
            &net::SocketAddr::from_abstract_name(this.abstract_unix.as_bytes()).unwrap(),
        )
        .unwrap();
        for listener in [filesystem, abstract_socket] {
            listener.set_nonblocking(true).unwrap();
            let listener = tokio::net::UnixListener::from_std(listener).unwrap();
            let count = this.counter();
            this.tasks.push(tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
            }));
        }
        this
    }
    fn counter(&mut self) -> Arc<AtomicUsize> {
        let count = Arc::new(AtomicUsize::new(0));
        self.counts.push(count.clone());
        count
    }
    pub fn snapshot(&self) -> Vec<usize> {
        assert!(
            self.tasks.iter().all(|task| !task.is_finished()),
            "canary failed"
        );
        self.counts
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .collect()
    }
    pub async fn positive_baseline(&self) -> Vec<usize> {
        // Each family is contacted by both the parent and its descendant;
        // the inherited network canary adds one IPv4 connection.
        let expected = vec![3, 2, 2, 2, 2, 2];
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let actual = self.snapshot();
                assert!(
                    actual
                        .iter()
                        .zip(&expected)
                        .all(|(actual, expected)| actual <= expected)
                );
                if actual == expected {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("positive controls did not reach every listener");
        expected
    }
}

impl Drop for Canaries {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
