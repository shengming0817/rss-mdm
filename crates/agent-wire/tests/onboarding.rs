use rss_mdm_agent_wire::{ManagedRegistrationRequest, ReportRequest};
use serde_json::json;
use uuid::Uuid;
#[test]
fn enrollment_reports_keep_unknown_and_third_party_distinct_from_unenrolled() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/report-request-v4.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for state in [
        "unenrolled",
        "this_organization",
        "other_organization",
        "unknown",
    ] {
        let value = json!({"wireVersion":4,"reportId":Uuid::new_v4(),"sequence":2,"observedAt":3,"body":{"kind":"mdmEnrollment","state":state}});
        let request: ReportRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), value);
        assert!(validator.is_valid(&value));
    }
    for state in ["offline", "absent", "permissionDenied"] {
        let value = json!({"wireVersion":4,"reportId":Uuid::new_v4(),"sequence":2,"observedAt":3,"body":{"kind":"mdmEnrollment","state":state}});
        assert!(serde_json::from_value::<ReportRequest>(value.clone()).is_err());
        assert!(!validator.is_valid(&value));
    }
}
#[test]
fn managed_registration_has_no_device_identity_or_bearer_claim() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/managed-registration-request-v4.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let value = json!({"wireVersion":4,"operationId":Uuid::new_v4(),"installationOperation":Uuid::new_v4(),"credential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","capabilities":["inventory.basic.v4"],"platform":"windows","architecture":"x86_64"});
    serde_json::from_value::<ManagedRegistrationRequest>(value.clone())
        .unwrap()
        .validate()
        .unwrap();
    assert!(validator.is_valid(&value));
    for key in [
        "deviceId",
        "tenantId",
        "registrationId",
        "password",
        "serialNumber",
    ] {
        let mut invalid = value.clone();
        invalid[key] = json!("untrusted");
        assert!(serde_json::from_value::<ManagedRegistrationRequest>(invalid.clone()).is_err());
        assert!(!validator.is_valid(&invalid));
    }
    let mut invalid = value;
    invalid["capabilities"] = json!(["inventory.basic.v4", "inventory.basic.v4"]);
    assert!(serde_json::from_value::<ManagedRegistrationRequest>(invalid).is_err());
}
