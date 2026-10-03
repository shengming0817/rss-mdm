use super::*;
struct Clock(Mutex<Instant>);
impl rss_observation::Clock for Clock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "test composition root supplies a controllable monotonic clock"
)]
fn peer_bursts_are_bounded_and_other_peers_recover() {
    let clock = Arc::new(Clock(Mutex::new(Instant::now())));
    let admission = Admission::new(
        clock.clone(),
        Arc::new(Semaphore::new(4)),
        "mdm-enrollment-tls",
    );
    let noisy = "127.0.0.2".parse().unwrap();
    let healthy = "127.0.0.1".parse().unwrap();
    let busy = (0..4)
        .map(|_| admission.connection(noisy).unwrap())
        .collect::<Vec<_>>();
    assert!(admission.connection(noisy).is_none());
    let healthy_connection = admission.connection(healthy).unwrap();
    let one = admission.request(noisy).unwrap();
    let two = admission.request(noisy).unwrap();
    assert!(admission.request(noisy).is_none());
    assert!(admission.request(healthy).is_some());
    drop((one, two, busy));
    let successes = (0..1000)
        .filter(|_| admission.request(healthy).is_some())
        .count();
    assert!(successes < 64);
    let connections = (0..1000)
        .filter(|_| admission.connection(noisy).is_some())
        .count();
    assert!(connections <= 12);
    *clock.0.lock().unwrap() += Duration::from_secs(60);
    assert!(admission.connection(noisy).is_some());
    assert!(admission.request(healthy).is_some());
    drop(healthy_connection);
}

#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "controlled monotonic clock at test composition root"
)]
async fn agent_keepalive_requests_consume_budget_and_return_family_errors() {
    use tower::ServiceExt;
    let clock = Arc::new(Clock(Mutex::new(Instant::now())));
    let admission = Admission::new(clock.clone(), Arc::new(Semaphore::new(4)), "agent-tls");
    let connection = admission.connection("127.0.0.1".parse().unwrap()).unwrap();
    let router = axum::Router::new()
        .fallback(|| async { axum::http::StatusCode::OK })
        .layer(axum::middleware::from_fn(admit_agent))
        .layer(Extension(connection.gate()));
    for _ in 0..64 {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/agent/runtime/v1/reports")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
    for (family, fields) in [("runtime", 1), ("enroll", 2)] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/api/agent/{family}/v1/status"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "1");
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body.as_object().unwrap().len(), fields);
        assert_eq!(body["code"], "service_unavailable");
    }
    *clock.0.lock().unwrap() += Duration::from_secs(60);
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/agent/runtime/v1/reports")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
