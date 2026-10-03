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
