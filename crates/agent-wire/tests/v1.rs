mod support;
use rss_mdm_agent_wire::{enroll, runtime};
use serde_json::json;
use uuid::Uuid;

#[test]
fn rebuilt_v1_rejects_retired_majors_and_historical_v1_shapes() {
    assert_eq!(enroll::API_VERSION, 1);
    assert_eq!(runtime::API_VERSION, 1);
    assert_eq!(runtime::WIRE_VERSION, 1);
    let collection = support::collection();
    let report = serde_json::to_value(
        runtime::ReportRequest::new(
            Uuid::new_v4(),
            1,
            1,
            collection,
            runtime::ReportBody::Snapshot(vec![]),
        )
        .unwrap(),
    )
    .unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/report-request-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&report));
    for version in [0, 2, 3, 4, 5, 6, 255] {
        let mut old = report.clone();
        old["wireVersion"] = json!(version);
        assert!(serde_json::from_value::<runtime::ReportRequest>(old.clone()).is_err());
        assert!(!validator.is_valid(&old));
    }
    let mut historical = report;
    historical.as_object_mut().unwrap().remove("collection");
    assert!(serde_json::from_value::<runtime::ReportRequest>(historical.clone()).is_err());
    assert!(!validator.is_valid(&historical));
    // The first V1 used enrollment passwords, claimed device IDs and inventory.basic.v1.
    let old_registration = json!({"wireVersion":1,"operationId":Uuid::new_v4(),
        "enrollmentId":Uuid::new_v4(),"password":"old-password","credential":"old-bearer",
        "deviceId":"claimed-device","capabilities":["inventory.basic.v1"]});
    assert!(serde_json::from_value::<enroll::CertificateRequest>(old_registration).is_err());
    for capability in [
        "inventory.basic.v1",
        "inventory.collect.v6",
        "task.execute.v6",
        "software.msi.system.v6",
        "mdm.enrollment.v6",
        "unknown.v1",
    ] {
        assert!(serde_json::from_value::<runtime::Capability>(json!(capability)).is_err());
    }
}

#[test]
fn credential_recovery_never_invents_a_verified_material_for_an_unattempted_mutation() {
    let mut result = runtime::CredentialResult {
        recovery: None,
        failure: None,
        definition_digest: [1; 32],
        complete: true,
        items: vec![],
    };
    assert!(result.validate().is_err());
    result.recovery = Some(runtime::CredentialRecoveryOutcome::NotAttempted);
    assert!(result.validate().is_ok());
    result.complete = false;
    assert!(result.validate().is_err());
    result.complete = true;
    result.failure = Some(runtime::CredentialFailure::RecoveryState);
    assert!(result.validate().is_err());
    result.failure = None;
    result.items.push(runtime::CredentialItemResult {
        subject: runtime::CredentialSubject::LocalAdministrator {
            sid: "S-1-5-21-1-2-3-500".into(),
        },
        outcome: runtime::CredentialOutcome::Verified,
    });
    assert!(result.validate().is_err());
}
