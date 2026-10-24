use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_timeline_service::{Query, project};
const TENANT: &str = "11111111-1111-4111-8111-111111111111";
#[test]
fn bounded_query_rejects_invalid_input() {
    assert!(Query::default().validate().is_ok());
    for limit in [0, 201, usize::MAX] {
        assert!(
            Query {
                limit: Some(limit),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        Query {
            from: Some(5),
            until: Some(4),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Query {
            operation_id: Some(uuid::Uuid::nil()),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(serde_json::from_str::<Query>(r#"{"permission":"audit_read"}"#).is_err());
}
#[test]
fn accepted_request_does_not_prove_execution_and_details_are_not_exposed() {
    let audit = RequestAudit::new(TENANT.into(), "command_accept");
    audit.target("device-a");
    let fact=Fact::business(&audit,"accept",b"input",202,"success",None).unwrap()
        .with_details(serde_json::json!({"token":"secret","stdout":"secret","phase":"verified","effect":"success"})).unwrap();
    let event = fact
        .event(rss_contract::Timepoint::try_from(5i64).unwrap())
        .unwrap();
    let view = project(&event).unwrap();
    assert_eq!(view.phase, "accepted");
    assert_eq!(view.effect, "unknown");
    assert!(!serde_json::to_string(&view).unwrap().contains("secret"));
    audit.finalize(None);
}
#[test]
fn unknown_action_and_outcome_never_become_success() {
    let audit = RequestAudit::new(TENANT.into(), "future_stage");
    let event = Fact::business(&audit, "phase", b"input", 503, "unknown", None)
        .unwrap()
        .event(rss_contract::Timepoint::try_from(5i64).unwrap())
        .unwrap();
    let view = project(&event).unwrap();
    assert_eq!(view.phase, "unknown");
    assert_eq!(view.audit_outcome, "unknown");
    assert_eq!(view.effect, "unknown");
    audit.finalize(None);
}

#[test]
fn resource_namespace_is_part_of_identity_and_projection() {
    use rss_mdm_audit_integration::TargetKind;
    let audit = RequestAudit::new(TENANT.into(), "management_write");
    audit.resource_target(TargetKind::Resource, "same-id");
    let resource = Fact::business(
        &audit,
        "same-operation",
        b"same-input",
        200,
        "success",
        None,
    )
    .unwrap();
    audit.resource_target(TargetKind::Policy, "same-id");
    let policy = Fact::business(
        &audit,
        "same-operation",
        b"same-input",
        200,
        "success",
        None,
    )
    .unwrap();
    let projected = project(
        &resource
            .event(rss_contract::Timepoint::try_from(5i64).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(projected).unwrap()["target"],
        serde_json::json!({"type":"resource","id":"same-id"})
    );
    let projected = project(
        &policy
            .event(rss_contract::Timepoint::try_from(5i64).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(projected).unwrap()["target"],
        serde_json::json!({"type":"policy","id":"same-id"})
    );
    audit.finalize(None);
}

#[test]
fn missing_targets_project_as_request_resources() {
    let audit = RequestAudit::new(TENANT.into(), "management_read");
    let fact = Fact::business(&audit, "missing-target", b"input", 400, "failed", None).unwrap();
    let view = project(
        &fact
            .event(rss_contract::Timepoint::try_from(5i64).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(view).unwrap()["target"],
        serde_json::json!({"type":"mdm","id":"request"})
    );
    audit.finalize(None);
}
