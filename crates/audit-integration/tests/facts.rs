use rss_mdm_audit_integration::{Fact, RequestAudit};
#[test]
fn business_retries_ignore_new_request_identity_but_detect_changed_facts() {
    let first = RequestAudit::new(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
        "device_action",
    );
    let second = RequestAudit::new(first.tenant().into(), "device_action");
    let a = Fact::business(
        &first,
        "operation.phase",
        b"request-A",
        200,
        "success",
        None,
    )
    .unwrap();
    let b = Fact::business(
        &second,
        "operation.phase",
        b"request-A",
        200,
        "success",
        None,
    )
    .unwrap();
    assert_eq!(a.fingerprint(), b.fingerprint());
    assert_eq!(
        a.identity().event_id().as_str(),
        b.identity().event_id().as_str()
    );
    let changed = Fact::business(
        &second,
        "operation.phase",
        b"request-A",
        503,
        "unknown",
        None,
    )
    .unwrap();
    assert_ne!(a.fingerprint(), changed.fingerprint());
    let changed_request = Fact::business(
        &second,
        "operation.phase",
        b"request-B",
        200,
        "success",
        None,
    )
    .unwrap();
    assert_eq!(
        a.identity().event_id().as_str(),
        changed_request.identity().event_id().as_str()
    );
    assert_ne!(a.fingerprint(), changed_request.fingerprint());
    let request = Fact::request(&first, 503, "unknown").unwrap();
    assert_ne!(
        a.identity().source().source_id().as_str(),
        request.identity().source().source_id().as_str()
    );
    first.finalize(None);
    second.finalize(None);
}
