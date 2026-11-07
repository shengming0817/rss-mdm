use rss_mdm_audit_integration::{Fact, RequestAudit};
fn canonical(fact: &Fact) -> Vec<u8> {
    let time = rss_contract::Timepoint::try_from(1i64).unwrap();
    rss_audit_core::prepare(fact.event(time).unwrap(), time)
        .unwrap()
        .canonical_bytes()
        .to_vec()
}
#[test]
fn business_identity_is_stable_but_originating_request_is_immutable() {
    let first = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
        "device_action",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let second = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        first.tenant().into(),
        "device_action",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let a = Fact::business(
        &first,
        rss_mdm_audit_integration::operation::OperationOwner::Resource,
        "operation.phase",
        200,
        "success",
        None,
    )
    .unwrap();
    let b = Fact::business(
        &second,
        rss_mdm_audit_integration::operation::OperationOwner::Resource,
        "operation.phase",
        200,
        "success",
        None,
    )
    .unwrap();
    // A retry must read the original receipt, never append a replacement business fact.
    assert_ne!(canonical(&a), canonical(&b));
    assert_eq!(
        a.identity().event_id().as_str(),
        b.identity().event_id().as_str()
    );
    let changed = Fact::business(
        &second,
        rss_mdm_audit_integration::operation::OperationOwner::Resource,
        "operation.phase",
        503,
        "unknown",
        None,
    )
    .unwrap();
    assert_ne!(canonical(&a), canonical(&changed));
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
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
        "device_action",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let fact = || {
        Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::Resource,
            "operation.phase",
            200,
            "success",
            None,
        )
        .unwrap()
    };
    let direct = fact()
        .with_details(serde_json::json!({"value": 2}))
        .unwrap();
    let replaced = fact()
        .with_details(serde_json::json!({"value": 1}))
        .unwrap()
        .with_details(serde_json::json!({"value": 2}))
        .unwrap();
    assert_eq!(canonical(&direct), canonical(&replaced));
    assert_ne!(canonical(&fact()), canonical(&direct));
    let event = direct
        .event(rss_contract::Timepoint::try_from(1_i64).unwrap())
        .unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(event.context().payload().as_bytes()).unwrap();
    assert_eq!(payload["details"], serde_json::json!({"value": 2}));
    audit.finalize(None);
}

#[test]
fn invalid_facts_expose_closed_categories_without_input_values() {
    use rss_mdm_audit_integration::InvalidFact;
    let context = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        "bad-secret-tenant".into(),
        "valid_action",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    assert!(matches!(
        Fact::request(&context, 200, "success"),
        Err(InvalidFact::Tenant)
    ));
    let valid = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        "11111111-1111-4111-8111-111111111111".into(),
        "valid_action",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    assert!(matches!(
        Fact::request(&valid, 600, "success"),
        Err(InvalidFact::Status)
    ));
    assert!(matches!(
        Fact::request(&valid, 200, "secret-result"),
        Err(InvalidFact::Outcome)
    ));
    assert!(matches!(
        Fact::business(
            &valid,
            rss_mdm_audit_integration::operation::OperationOwner::Resource,
            "",
            200,
            "success",
            None
        ),
        Err(InvalidFact::Identity)
    ));
    context.finalize(None);
    valid.finalize(None);
}

#[test]
fn device_request_coordinates_are_explicit_and_generic_targets_clear_them() {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_audit_integration::StorageProfile::Mdm,
        "11111111-1111-4111-8111-111111111111".into(),
        "management_write",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device("device-a");
    let payload = |fact: Fact| {
        let event = fact
            .event(rss_contract::Timepoint::try_from(1i64).unwrap())
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(event.context().payload().as_bytes()).unwrap()
    };
    assert_eq!(
        payload(Fact::request(&audit, 403, "denied").unwrap())["details"]["deviceId"],
        "device-a"
    );
    audit.target("saved-query-id");
    assert!(payload(Fact::request(&audit, 403, "denied").unwrap())["details"].is_null());
    audit.finalize(None);
}

#[test]
fn product_source_survives_context_projection() {
    use rss_mdm_audit_integration::{AuditIntent, StorageProfile};
    let mut identities = Vec::new();
    for profile in [StorageProfile::Mdm, StorageProfile::Da] {
        let context = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Request,
            profile,
            "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
            "device_action",
            AuditIntent::Management,
        );
        context.identify_service("same-service");
        let fact = Fact::business(
            &context,
            rss_mdm_audit_integration::operation::OperationOwner::Resource,
            "same-operation",
            200,
            "success",
            None,
        )
        .unwrap();
        for copy in [
            context.transaction_copy(),
            context.fact_copy("device_action"),
        ] {
            assert_eq!(copy.profile(), profile);
            assert_eq!(
                canonical(
                    &Fact::business(
                        &copy,
                        rss_mdm_audit_integration::operation::OperationOwner::Resource,
                        "same-operation",
                        200,
                        "success",
                        None
                    )
                    .unwrap()
                ),
                canonical(&fact)
            );
            copy.finalize(None);
        }
        identities.push(fact.identity().source().source_id().as_str().to_owned());
        context.finalize(None);
    }
    assert_eq!(identities, ["mdm.business", "da.business"]);
}

#[test]
fn background_facts_do_not_invent_request_causality_or_write_outcomes() {
    use rss_mdm_audit_integration::operation::OperationOwner;
    use rss_mdm_audit_integration::{AuditIntent, Origin, StorageProfile};
    for origin in [Origin::Request, Origin::Background] {
        let audit = RequestAudit::new(
            origin,
            StorageProfile::Mdm,
            "11111111-1111-4111-8111-111111111111".into(),
            "command_accept",
            AuditIntent::Management,
        );
        let id = uuid::Uuid::new_v4();
        audit.operation(id, "command_accept", AuditIntent::Management);
        let event = Fact::business(
            &audit,
            OperationOwner::DeviceControl,
            "accept",
            202,
            "success",
            None,
        )
        .unwrap()
        .event(rss_contract::Timepoint::try_from(1i64).unwrap())
        .unwrap();
        assert_eq!(
            event.context().coordinates().request_id().is_some(),
            origin == Origin::Request
        );
        let payload: serde_json::Value =
            serde_json::from_slice(event.context().payload().as_bytes()).unwrap();
        assert!(payload["writeOutcome"].is_null());
        assert_eq!(payload["operationLocator"]["operationId"], id.to_string());
        assert_eq!(payload["operationLocator"]["owner"], "device_control");
        audit.finalize(None);
    }
}

#[test]
fn replay_request_and_tenant_child_keep_only_explicit_coordinates() {
    use rss_mdm_audit_integration::operation::OperationOwner as O;
    use rss_mdm_audit_integration::{AuditIntent, Origin, StorageProfile};
    let audit = RequestAudit::new(
        Origin::Request,
        StorageProfile::Mdm,
        "11111111-1111-4111-8111-111111111111".into(),
        "write",
        AuditIntent::Management,
    );
    audit.set_principal("actor", "22222222-2222-4222-8222-222222222222");
    let id = uuid::Uuid::new_v4();
    audit.owned_operation(O::Resource, id, "write", AuditIntent::Management);
    audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
    let replay = Fact::request(&audit, 200, "replay")
        .unwrap()
        .event(rss_contract::Timepoint::try_from(1i64).unwrap())
        .unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(replay.context().payload().as_bytes()).unwrap();
    assert_eq!(payload["operationLocator"]["owner"], "resource");
    assert_eq!(payload["operationLocator"]["actor"], "actor");
    let child = audit.tenant_fact_copy("33333333-3333-4333-8333-333333333333".into(), "child");
    assert_eq!(child.request_coordinate(), audit.request_coordinate());
    let event = Fact::business(&child, O::Resource, "child", 200, "success", None)
        .unwrap()
        .event(rss_contract::Timepoint::try_from(1i64).unwrap())
        .unwrap();
    assert_eq!(event.identity().tenant().to_string(), child.tenant());
    audit.operation(uuid::Uuid::new_v4(), "protocol", AuditIntent::Routine);
    let event = Fact::request(&audit, 200, "success")
        .unwrap()
        .event(rss_contract::Timepoint::try_from(1i64).unwrap())
        .unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(event.context().payload().as_bytes()).unwrap();
    assert!(payload["operationLocator"].is_null());
    audit.finalize(None);
}

#[test]
fn rejected_nil_operation_does_not_prevent_recording_the_request_attempt() {
    use rss_mdm_audit_integration::{
        AuditIntent, Origin, StorageProfile, operation::OperationOwner,
    };
    let a = RequestAudit::new(
        Origin::Request,
        StorageProfile::Mdm,
        "11111111-1111-4111-8111-111111111111".into(),
        "invalid",
        AuditIntent::Management,
    );
    a.owned_operation(
        OperationOwner::Resource,
        uuid::Uuid::nil(),
        "invalid",
        AuditIntent::Management,
    );
    let event = Fact::request(&a, 400, "rejected")
        .unwrap()
        .event(rss_contract::Timepoint::try_from(1i64).unwrap())
        .unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(event.context().payload().as_bytes()).unwrap();
    assert!(payload["operationLocator"].is_null());
    assert!(event.context().coordinates().request_id().is_some());
    a.finalize(None);
}

#[test]
fn receipt_subject_is_not_the_authenticated_actor_or_a_run_namespace() {
    use rss_mdm_audit_integration::{
        AuditIntent, Origin, StorageProfile, operation::OperationOwner as O,
    };
    let audit = RequestAudit::new(
        Origin::Request,
        StorageProfile::Mdm,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
        "self_service_invoke",
        AuditIntent::Management,
    );
    let registration = uuid::Uuid::new_v4();
    audit.identify_device(registration);
    let request = uuid::Uuid::new_v4();
    audit.owned_operation(
        O::ScriptInvocation,
        request,
        "self_service_invoke",
        AuditIntent::Management,
    );
    audit.receipt_actor(&format!("self-service:device:{registration}:1"));
    audit.registration_at(registration, 1);
    let fact = Fact::business(
        &audit,
        O::ScriptInvocation,
        "invocation",
        202,
        "success",
        None,
    )
    .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(
        fact.event(rss_contract::Timepoint::try_from(1_i64).unwrap())
            .unwrap()
            .context()
            .payload()
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(payload["operationLocator"]["owner"], "script_invocation");
    assert_eq!(
        payload["operationLocator"]["actor"],
        format!("self-service:device:{registration}:1")
    );
    assert_eq!(
        audit.snapshot().actor,
        Some(format!("device:{registration}"))
    );
    let run = audit.fact_copy("script_accept");
    run.owned_operation(
        O::Script,
        uuid::Uuid::new_v4(),
        "script_accept",
        AuditIntent::Management,
    );
    assert_eq!(run.request_coordinate(), Some(audit.request_id()));
    assert!(run.snapshot().receipt_actor.is_none());
    assert_eq!(audit.snapshot().operation_id, Some(request));
    audit.finalize(None);
}
