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
