use super::*;
#[tokio::test]
async fn gateway_source_budgets_are_isolated_and_release_on_drop() {
    let owner = Admission::new(
        crate::test_support::runtime::monotonic(),
        Arc::new(Semaphore::new(8)),
        "device-http",
    );
    let first: IpAddr = "192.0.2.1".parse().unwrap();
    let second: IpAddr = "192.0.2.2".parse().unwrap();
    owner.gate(first).unwrap();
    owner.gate(second).unwrap();
    let a = owner.peer_request(first).unwrap();
    let b = owner.peer_request(first).unwrap();
    assert!(owner.peer_request(first).is_none());
    assert!(owner.peer_request(second).is_some());
    drop(a);
    assert!(owner.peer_request(first).is_some());
    drop(b);
}
