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

#[test]
fn detail_replacement_depends_only_on_final_facts() {
    let audit = RequestAudit::new(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
        "device_action",
    );
    let fact =
        || Fact::business(&audit, "operation.phase", b"request", 200, "success", None).unwrap();
    let direct = fact()
        .with_details(serde_json::json!({"value": 2}))
        .unwrap();
    let replaced = fact()
        .with_details(serde_json::json!({"value": 1}))
        .unwrap()
        .with_details(serde_json::json!({"value": 2}))
        .unwrap();
    assert_eq!(direct.fingerprint(), replaced.fingerprint());
    assert_ne!(fact().fingerprint(), direct.fingerprint());
    assert_ne!(
        fact()
            .with_details(serde_json::json!({"value": 1}))
            .unwrap()
            .fingerprint(),
        direct.fingerprint()
    );
    let event = direct
        .event(rss_contract::Timepoint::try_from(1_i64).unwrap())
        .unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(event.context().payload().as_bytes()).unwrap();
    assert_eq!(payload["details"], serde_json::json!({"value": 2}));
    audit.finalize(None);
}
