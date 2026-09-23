use super::*;

async fn connections(origin: &Origin, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while origin.active_connections() != expected {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("retained unpolled response kept its upstream connection alive");
}

async fn origin() -> Origin {
    Origin::with_handler(|request| {
        if request.target.path() == "/positive" {
            Reply::body("positive")
        } else {
            let mut reply = Reply::body("unfinished");
            reply.delay = Duration::from_secs(30);
            reply
        }
    })
    .await
}

async fn execute(
    transport: &HttpsTransport,
    origin: &Origin,
    limits: Limits,
    cancelled: Cancellation,
) -> Response {
    transport
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            request(&origin.origin()),
            limits,
            cancelled,
        )
        .await
        .unwrap()
}

async fn positive(transport: &HttpsTransport, origin: &Origin) {
    let mut input = request(&origin.origin());
    *input.uri_mut() = format!("{}/positive", origin.origin()).parse().unwrap();
    let response = transport
        .execute(
            Endpoint::new(&origin.origin(), origin.address).unwrap(),
            input,
            Limits::default(),
            Cancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "positive"
    );
}

#[tokio::test]
async fn cancellation_closes_unpolled_connection_without_cancelling_its_peer() {
    let origin = origin().await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    positive(&transport, &origin).await;
    connections(&origin, 0).await;
    let first = Cancellation::default();
    let second = Cancellation::default();
    let held = execute(&transport, &origin, Limits::default(), first.clone()).await;
    let peer = execute(&transport, &origin, Limits::default(), second.clone()).await;
    assert_eq!(origin.active_connections(), 2);
    first.cancel();
    connections(&origin, 1).await;
    assert!(!second.is_cancelled());
    positive(&transport, &origin).await;
    connections(&origin, 1).await;
    assert!(held.into_body().collect().await.is_err());
    second.cancel();
    connections(&origin, 0).await;
    assert!(peer.into_body().collect().await.is_err());
    assert_eq!(origin.accepted_connections(), 4);
    assert_eq!(origin.requests.lock().unwrap().len(), 4);
}

async fn unpolled_deadline(total: bool) {
    let origin = origin().await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    positive(&transport, &origin).await;
    connections(&origin, 0).await;
    let limits = if total {
        Limits {
            total_timeout: Duration::from_millis(300),
            ..Limits::default()
        }
    } else {
        Limits {
            idle_timeout: Duration::from_millis(300),
            ..Limits::default()
        }
    };
    let held = execute(&transport, &origin, limits, Cancellation::default()).await;
    assert_eq!(origin.active_connections(), 1);
    connections(&origin, 0).await;
    assert!(
        matches!(held.into_body().collect().await, Err(error) if error.code == ErrorCode::OutcomeUnknown)
    );
    positive(&transport, &origin).await;
    assert_eq!(origin.accepted_connections(), 3);
    assert_eq!(origin.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn idle_deadline_closes_an_unpolled_response_connection() {
    unpolled_deadline(false).await;
}

#[tokio::test]
async fn total_deadline_closes_an_unpolled_response_connection() {
    unpolled_deadline(true).await;
}

#[tokio::test]
async fn driver_wait_retains_unfinished_work_and_joins_after_body_drop() {
    let origin = origin().await;
    let transport = HttpsTransport::new([origin.certificate.clone()]).unwrap();
    let drivers = transport.http_drivers();
    let held = execute(
        &transport,
        &origin,
        Limits::default(),
        Cancellation::default(),
    )
    .await;
    assert_eq!(origin.active_connections(), 1);
    assert_eq!(
        drivers.status().tasks_pending,
        1,
        "live driver was not owned"
    );
    let report = drivers
        .wait_until_idle(Instant::now() + Duration::from_millis(10))
        .await;
    assert_eq!(report.tasks_pending, 1, "timeout forgot unfinished work");
    assert!(!report.join_failed);
    drop(transport);
    assert_eq!(origin.active_connections(), 1);
    drop(held);
    let report = drivers
        .wait_until_idle(Instant::now() + Duration::from_secs(2))
        .await;
    assert_eq!(report.tasks_pending, 0);
    assert!(!report.join_failed);
    connections(&origin, 0).await;
    assert_eq!(origin.requests.lock().unwrap().len(), 1);
}
