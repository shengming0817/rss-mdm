//! Current PKI V1 static boundaries and stable service installation bytes.
use rss_mdm_agent_wire::{pki, runtime};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/pki-v1-vectors.json")).unwrap()
}
fn trust_json() -> Value {
    serde_json::from_str(vectors()["trustJson"].as_str().unwrap()).unwrap()
}
fn ack_json() -> Value {
    serde_json::from_str(vectors()["acknowledgementJson"].as_str().unwrap()).unwrap()
}
fn observation_json() -> Value {
    json!({"operation":Uuid::from_u128(1),"version":1,"registration":Uuid::from_u128(2),
        "generation":1,"sequence":1,"target_revision":null,"target_digest":null,
        "actual_revision":null,"actual_digest":null,"state":"unknown","reason":"restart","observed_at":1})
}
fn validator(trust: bool) -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(if trust {
        include_str!("../schema/pki/trust-v1.schema.json")
    } else {
        include_str!("../schema/pki/acknowledgement-v1.schema.json")
    })
    .unwrap();
    jsonschema::validator_for(&schema).unwrap()
}
fn accepted(value: &Value, trust: bool) -> bool {
    if trust {
        serde_json::from_value::<pki::Trust>(value.clone()).is_ok()
    } else {
        serde_json::from_value::<pki::Acknowledgement>(value.clone()).is_ok()
    }
}

#[test]
fn pki_artifact_is_complete_and_independent() {
    let manifest: Value = serde_json::from_str(pki::SCHEMA_MANIFEST).unwrap();
    assert_eq!(manifest["apiVersion"], pki::API_VERSION);
    let mut digest = Sha256::new();
    for entry in manifest["schemas"].as_array().unwrap() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("schema/pki")
            .join(entry["file"].as_str().unwrap());
        let bytes = std::fs::read(path).unwrap();
        let schema: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            schema["$id"],
            format!(
                "https://rss.example/agent/pki/v1/{}",
                entry["type"].as_str().unwrap()
            )
        );
        let validator = jsonschema::validator_for(&schema).unwrap();
        let value = match entry["type"].as_str().unwrap() {
            "Trust" => trust_json(),
            "Acknowledgement" => ack_json(),
            "Observation" => observation_json(),
            "ObservedInstallation" => json!({"observation":observation_json(),"received_at":1}),
            unexpected => panic!("unexpected PKI root: {unexpected}"),
        };
        assert!(validator.is_valid(&value));
        digest.update(bytes);
    }
    assert_eq!(format!("{:x}", digest.finalize()), pki::SCHEMA_FINGERPRINT);
    assert_ne!(pki::SCHEMA_FINGERPRINT, runtime::SCHEMA_FINGERPRINT);
}

#[test]
fn rust_and_schema_reject_the_same_malformed_coordinates() {
    for trust in [true, false] {
        let valid = if trust { trust_json() } else { ack_json() };
        let validator = validator(trust);
        assert!(validator.is_valid(&valid));
        assert!(accepted(&valid, trust));
        for field in valid.as_object().unwrap().keys() {
            let mut invalid = valid.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(!validator.is_valid(&invalid), "missing {field}");
            assert!(!accepted(&invalid, trust), "missing {field}");
        }
        let coordinate = if trust { "tenant" } else { "operation" };
        for (field, value) in [
            ("unexpected", json!(null)),
            ("version", json!(0)),
            ("version", json!(2)),
            ("version", json!(256)),
            ("version", json!("1")),
            (coordinate, json!(Uuid::nil())),
            (coordinate, json!("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")),
            (coordinate, json!("aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa")),
            (coordinate, json!(null)),
            ("revision", json!(0)),
            ("revision", json!(i64::MAX as u64 + 1)),
            ("revision", json!(-1)),
            ("revision", json!(1.5)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(
                !validator.is_valid(&invalid),
                "schema: {field}={}",
                invalid[field]
            );
            assert!(
                !accepted(&invalid, trust),
                "Rust: {field}={}",
                invalid[field]
            );
        }
        for revision in [1, i64::MAX as u64] {
            let mut boundary = valid.clone();
            boundary["revision"] = json!(revision);
            assert!(validator.is_valid(&boundary));
            assert!(accepted(&boundary, trust));
        }
    }
}

#[test]
fn issuer_fields_enums_and_digests_are_closed() {
    let trust = trust_json();
    let ack = ack_json();
    for value in [
        "".into(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        format!("{}\n", "a".repeat(64)),
    ] {
        let mut malformed = trust.clone();
        malformed["issuers"][0]["digest"] = json!(value);
        assert!(!validator(true).is_valid(&malformed));
        assert!(!accepted(&malformed, true));
        let mut malformed = ack.clone();
        malformed["digest"] = json!(value);
        assert!(!validator(false).is_valid(&malformed));
        assert!(!accepted(&malformed, false));
    }
    for field in trust["issuers"][0].as_object().unwrap().keys() {
        let mut malformed = trust.clone();
        malformed["issuers"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            !validator(true).is_valid(&malformed),
            "missing issuer {field}"
        );
        assert!(!accepted(&malformed, true));
    }
    for (pointer, value) in [
        ("/purpose", json!("unknown")),
        ("/issuers/0/mode", json!("retired")),
        ("/issuers/0/certificate", json!(null)),
    ] {
        let mut malformed = trust.clone();
        *malformed.pointer_mut(pointer).unwrap() = value;
        assert!(!validator(true).is_valid(&malformed));
        assert!(!accepted(&malformed, true));
    }
    let mut malformed = trust;
    malformed["issuers"][0]["unexpected"] = json!(null);
    assert!(!validator(true).is_valid(&malformed));
    assert!(!accepted(&malformed, true));
}

#[test]
fn issuer_sets_are_bounded_and_keep_shared_purposes() {
    let valid = trust_json();
    let validator = validator(true);
    for count in [0, 1, 16, 17] {
        let mut value = valid.clone();
        value["issuers"] = json!(
            (0..count)
                .map(|i| {
                    let mut issuer = valid["issuers"][usize::from(i != 0)].clone();
                    issuer["digest"] = json!(format!("{i:064x}"));
                    issuer
                })
                .collect::<Vec<_>>()
        );
        let expected = (1..=16).contains(&count);
        assert_eq!(validator.is_valid(&value), expected);
        assert_eq!(accepted(&value, true), expected);
    }
    for mode in ["prepared", "verify_only"] {
        let mut value = valid.clone();
        value["issuers"][0]["mode"] = json!(mode);
        assert!(!validator.is_valid(&value));
        assert!(!accepted(&value, true));
    }
    let mut value = valid.clone();
    value["issuers"][1]["mode"] = json!("active");
    assert!(!validator.is_valid(&value));
    assert!(!accepted(&value, true));
    for purpose in ["agent", "windows", "apple"] {
        let mut value = valid.clone();
        value["purpose"] = json!(purpose);
        value["issuers"][1]["provisioner"] = json!("");
        value["issuers"][1]["kid"] = json!("");
        assert!(validator.is_valid(&value));
        assert!(accepted(&value, true));
    }
}

#[test]
fn direct_rust_construction_uses_the_same_static_checks() {
    let trust: pki::Trust = serde_json::from_value(trust_json()).unwrap();
    let ack: pki::Acknowledgement = serde_json::from_value(ack_json()).unwrap();
    assert!(trust.validate().is_ok());
    assert!(ack.validate().is_ok());
    for field in [
        "version", "revision", "tenant", "issuers", "digest", "active",
    ] {
        let mut value = trust.clone();
        match field {
            "version" => value.version = 2,
            "revision" => value.revision = 0,
            "tenant" => value.tenant = Uuid::nil(),
            "issuers" => value.issuers.clear(),
            "digest" => value.issuers[0].digest.clear(),
            "active" => value.issuers[1].mode = pki::Mode::Active,
            _ => unreachable!(),
        }
        assert!(value.validate().is_err(), "{field}");
    }
    for field in ["version", "revision", "operation", "digest"] {
        let mut value = ack.clone();
        match field {
            "version" => value.version = 2,
            "revision" => value.revision = i64::MAX as u64 + 1,
            "operation" => value.operation = Uuid::nil(),
            "digest" => value.digest.clear(),
            _ => unreachable!(),
        }
        assert!(value.validate().is_err(), "{field}");
    }
}

#[test]
fn exact_json_and_installation_binding_use_stable_service_identity() {
    let vectors = vectors();
    let trust: pki::Trust = serde_json::from_str(vectors["trustJson"].as_str().unwrap()).unwrap();
    let ack: pki::Acknowledgement =
        serde_json::from_str(vectors["acknowledgementJson"].as_str().unwrap()).unwrap();
    assert_eq!(serde_json::to_string(&trust).unwrap(), vectors["trustJson"]);
    assert_eq!(
        serde_json::to_string(&ack).unwrap(),
        vectors["acknowledgementJson"]
    );
    assert_eq!(trust.installation_digest(), vectors["installationDigest"]);
    for root in [false, true] {
        let mut refreshed = trust.clone();
        if root {
            refreshed.issuers[0].root_crl = "updated".into();
        } else {
            refreshed.issuers[0].crl = "updated".into();
        }
        assert_eq!(refreshed.installation_digest(), trust.installation_digest());
    }
    let mut relocated = trust.clone();
    relocated.origin = "https://other.example".into();
    assert_eq!(relocated.installation_digest(), trust.installation_digest());
    for field in [
        "service_id",
        "tenant",
        "purpose",
        "revision",
        "order",
        "mode",
        "digest",
        "certificate",
        "root",
        "provisioner",
        "kid",
    ] {
        let mut changed = trust.clone();
        match field {
            "service_id" => changed.service_id = ack.operation,
            "tenant" => changed.tenant = ack.operation,
            "purpose" => changed.purpose = pki::Purpose::Windows,
            "revision" => changed.revision += 1,
            "order" => changed.issuers.reverse(),
            "mode" => changed.issuers[1].mode = pki::Mode::Prepared,
            "digest" => changed.issuers[0].digest = "c".repeat(64),
            "certificate" => changed.issuers[0].certificate = "changed".into(),
            "root" => changed.issuers[0].root = "changed".into(),
            "provisioner" => changed.issuers[0].provisioner = "changed".into(),
            "kid" => changed.issuers[0].kid = "changed".into(),
            _ => unreachable!(),
        }
        assert_ne!(
            changed.installation_digest(),
            trust.installation_digest(),
            "{field}"
        );
    }
}

#[test]
fn observation_rejects_false_applied_and_unbounded_or_ambiguous_coordinates() {
    use rss_mdm_agent_wire::pki::{Observation, ObservationReason, ObservationState};
    let mut value = Observation {
        operation: uuid::Uuid::new_v4(),
        version: 1,
        registration: uuid::Uuid::new_v4(),
        generation: 1,
        sequence: 1,
        target_revision: Some(2),
        target_digest: Some("a".repeat(64)),
        actual_revision: Some(1),
        actual_digest: Some("b".repeat(64)),
        state: ObservationState::Failed,
        reason: Some(ObservationReason::Storage),
        observed_at: 1,
    };
    assert!(value.validate().is_ok());
    value.state = ObservationState::Applied;
    value.reason = None;
    assert!(value.validate().is_err());
    value.actual_revision = value.target_revision;
    value.actual_digest = value.target_digest.clone();
    assert!(value.validate().is_ok());
    value.sequence = u64::MAX;
    assert!(value.validate().is_err());
    value.sequence = 1;
    value.actual_digest = None;
    assert!(value.validate().is_err());
    value.actual_revision = None;
    value.state = ObservationState::Unknown;
    assert!(value.validate().is_err());
    value.reason = Some(ObservationReason::Restart);
    assert!(value.validate().is_ok());
}

#[test]
fn observation_schema_rejects_invalid_coordinates() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/pki/observation-v1.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let valid = serde_json::json!({"operation":uuid::Uuid::from_u128(1),"version":1,"registration":uuid::Uuid::from_u128(2),
        "generation":1,"sequence":1,"target_revision":null,"target_digest":null,
        "actual_revision":null,"actual_digest":null,"state":"unknown","reason":"restart","observed_at":1});
    assert!(validator.is_valid(&valid));
    for (field, value) in [
        ("version", serde_json::json!(0)),
        ("generation", serde_json::json!(0)),
        ("sequence", serde_json::json!(u64::MAX)),
        ("target_revision", serde_json::json!(0)),
        ("actual_revision", serde_json::json!(u64::MAX)),
        ("observed_at", serde_json::json!(-1)),
        ("target_digest", serde_json::json!("bad")),
        ("actual_digest", serde_json::json!("A".repeat(64))),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(!validator.is_valid(&invalid), "{field}");
        assert!(
            serde_json::from_value::<rss_mdm_agent_wire::pki::Observation>(invalid)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
