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
