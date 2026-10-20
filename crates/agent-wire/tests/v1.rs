mod support;
use rss_mdm_agent_wire::{enroll, runtime};
use serde_json::json;
use uuid::Uuid;

#[test]
fn current_report_requires_its_collection_and_supported_wire() {
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
    for version in [0, 255] {
        let mut old = report.clone();
        old["wireVersion"] = json!(version);
        assert!(serde_json::from_value::<runtime::ReportRequest>(old.clone()).is_err());
        assert!(!validator.is_valid(&old));
    }
    let mut incomplete = report;
    incomplete.as_object_mut().unwrap().remove("collection");
    assert!(serde_json::from_value::<runtime::ReportRequest>(incomplete.clone()).is_err());
    assert!(!validator.is_valid(&incomplete));
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
