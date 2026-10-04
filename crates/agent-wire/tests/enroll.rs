use rss_mdm_agent_wire::{enroll as wire, runtime};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[test]
fn enrollment_has_an_independent_complete_artifact() {
    let manifest: Value = serde_json::from_str(wire::SCHEMA_MANIFEST).unwrap();
    assert_eq!(manifest["apiVersion"], 1);
    let mut digest = Sha256::new();
    for entry in manifest["schemas"].as_array().unwrap() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("schema/enroll")
            .join(entry["file"].as_str().unwrap());
        let bytes = std::fs::read(path).unwrap();
        jsonschema::validator_for(&serde_json::from_slice::<Value>(&bytes).unwrap()).unwrap();
        digest.update(bytes);
    }
    assert_eq!(format!("{:x}", digest.finalize()), wire::SCHEMA_FINGERPRINT);
    assert_ne!(wire::SCHEMA_FINGERPRINT, runtime::SCHEMA_FINGERPRINT);
}
#[test]
fn bootstrap_is_closed_and_cannot_claim_a_device_or_runtime_credential() {
    let value = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","platform":"macos"});
    let request: wire::GrantRequest = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(format!("{:?}", request.secret), "[REDACTED]");
    let schema: Value = serde_json::from_str(include_str!(
        "../schema/enroll/grant-request-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&value));
    for (key, v) in [
        ("deviceId", json!("claimed")),
        ("credential", json!("bearer")),
        ("wireVersion", json!(6)),
        ("operationId", json!(Uuid::nil())),
    ] {
        let mut invalid = value.clone();
        invalid[key] = v;
        assert!(serde_json::from_value::<wire::GrantRequest>(invalid.clone()).is_err());
        assert!(!validator.is_valid(&invalid));
    }
}

#[test]
fn renewal_lookup_requires_only_the_original_operation_and_secret() {
    let value = json!({"wireVersion":1,"operationId":Uuid::new_v4(),"secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
    let schema: Value = serde_json::from_str(include_str!(
        "../schema/enroll/renewal-status-request-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&value));
    let request: wire::RenewalStatusRequest = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(format!("{:?}", request.secret), "[REDACTED]");
    for (field, invalid) in [
        ("wireVersion", json!(2)),
        ("operationId", json!(Uuid::nil())),
        ("secret", json!("invalid")),
        ("grantId", json!(Uuid::new_v4())),
        ("registrationId", json!(Uuid::new_v4())),
    ] {
        let mut input = value.clone();
        input[field] = invalid;
        assert!(!validator.is_valid(&input));
        assert!(serde_json::from_value::<wire::RenewalStatusRequest>(input).is_err());
    }
    for field in ["wireVersion", "operationId", "secret"] {
        let mut input = value.clone();
        input.as_object_mut().unwrap().remove(field);
        assert!(!validator.is_valid(&input));
        assert!(serde_json::from_value::<wire::RenewalStatusRequest>(input).is_err());
    }
}

#[test]
fn nullable_response_fields_are_required_and_uuid_values_are_canonical() {
    let schema: Value =
        serde_json::from_str(include_str!("../schema/enroll/error-body-v1.schema.json")).unwrap();
    let validate = jsonschema::validator_for(&schema).unwrap();
    for id in [json!(null), json!(Uuid::new_v4())] {
        let value = json!({"code":"issuance_unknown","issuanceId":id});
        assert!(validate.is_valid(&value));
        assert!(serde_json::from_value::<wire::ErrorBody>(value).is_ok());
    }
    for value in [
        json!({"code":"issuance_unknown"}),
        json!({"code":"issuance_unknown","issuanceId":Uuid::nil()}),
        json!({"code":"issuance_unknown","issuanceId":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}),
        json!({"code":"issuance_unknown","issuanceId":"aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"}),
    ] {
        assert!(!validate.is_valid(&value));
        assert!(serde_json::from_value::<wire::ErrorBody>(value).is_err());
    }
    let schema: Value =
        serde_json::from_str(include_str!("../schema/enroll/progress-v1.schema.json")).unwrap();
    let validate = jsonschema::validator_for(&schema).unwrap();
    let value = json!({"grant":{"wireVersion":1,"grantId":Uuid::new_v4(),"state":"pending","expiresAt":1,"platform":"macos"},"issuanceId":null,"issuanceUnknown":false,"activation":null});
    assert!(validate.is_valid(&value));
    assert!(serde_json::from_value::<wire::Progress>(value.clone()).is_ok());
    for field in ["issuanceId", "activation"] {
        let mut invalid = value.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(!validate.is_valid(&invalid));
        assert!(serde_json::from_value::<wire::Progress>(invalid).is_err());
    }
}
