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
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        TENANT.into(),
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target("device-a");
    let fact=Fact::business(&audit, rss_mdm_audit_integration::operation::OperationOwner::DeviceControl, "accept", 202, "success", None).unwrap()
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
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        TENANT.into(),
        "future_stage",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let event = Fact::business(
        &audit,
        rss_mdm_audit_integration::operation::OperationOwner::DeviceControl,
        "phase",
        503,
        "unknown",
        None,
    )
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
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        TENANT.into(),
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.resource_target(TargetKind::Resource, "same-id");
    let resource = Fact::business(
        &audit,
        rss_mdm_audit_integration::operation::OperationOwner::DeviceControl,
        "same-operation",
        200,
        "success",
        None,
    )
    .unwrap();
    audit.resource_target(TargetKind::Policy, "same-id");
    let policy = Fact::business(
        &audit,
        rss_mdm_audit_integration::operation::OperationOwner::DeviceControl,
        "same-operation",
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
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        TENANT.into(),
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let fact = Fact::business(
        &audit,
        rss_mdm_audit_integration::operation::OperationOwner::DeviceControl,
        "missing-target",
        400,
        "failed",
        None,
    )
    .unwrap();
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

#[test]
fn request_and_owner_filters_are_signed_query_dimensions() {
    let id = uuid::Uuid::new_v4();
    let q = Query::parse(&format!("requestId={id}&owner=policy&limit=2"), false).unwrap();
    assert_eq!(q.request_id, Some(id));
    assert_eq!(
        q.owner,
        Some(rss_mdm_audit_integration::operation::OperationOwner::Policy)
    );
    assert!(Query::parse("requestId=00000000-0000-0000-0000-000000000000", false).is_err());
    assert!(Query::parse("owner=guessed_from_hash", false).is_err());
}

#[test]
fn background_attempt_is_not_an_http_request_even_when_using_request_settlement() {
    use rss_mdm_audit_integration::{AuditIntent, Origin, StorageProfile};
    for origin in [Origin::Request, Origin::Background] {
        let audit = RequestAudit::new(
            origin,
            StorageProfile::Mdm,
            TENANT.into(),
            "recovery",
            AuditIntent::Management,
        );
        let fact = Fact::request(&audit, 503, "unknown").unwrap();
        let view = project(
            &fact
                .event(rss_contract::Timepoint::try_from(1i64).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(view.origin, Some(origin));
        assert_eq!(view.request_id.is_some(), origin == Origin::Request);
        assert_eq!(
            view.phase,
            if origin == Origin::Request {
                "request"
            } else {
                "background_attempt"
            }
        );
        audit.finalize(None);
    }
}

#[test]
fn request_replay_remains_a_request_observation_not_a_second_business_fact() {
    use rss_mdm_audit_integration::{AuditIntent, Origin, StorageProfile};
    let audit = RequestAudit::new(
        Origin::Request,
        StorageProfile::Mdm,
        TENANT.into(),
        "management_write",
        AuditIntent::Management,
    );
    let view = project(
        &Fact::request(&audit, 200, "replay")
            .unwrap()
            .event(rss_contract::Timepoint::try_from(1i64).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(view.request_replayed);
    assert_eq!(view.phase, "request");
    assert_eq!(
        view.request_write_outcome.as_deref(),
        Some("commit_not_started")
    );
    audit.finalize(None);
}

#[test]
fn push_observations_retain_the_producer_device_without_an_operation_locator() {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        TENANT.into(),
        "windows_push",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("service:windows-push");
    let device = rss_mdm_agent_wire::DeviceId::new_v4();
    audit.target_device(&device);
    let event = Fact::observation(&audit, "wake:lease", 200, "success", None)
        .unwrap()
        .event(rss_contract::Timepoint::try_from(5i64).unwrap())
        .unwrap();
    let view = project(&event).unwrap();
    assert_eq!(view.device_id, Some(device));
    assert!(view.operation_id.is_none());
    audit.finalize(None);
}
