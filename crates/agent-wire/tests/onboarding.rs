mod support;
use rss_mdm_agent_wire::runtime::ReportRequest;
use serde_json::json;
use uuid::Uuid;
#[test]
fn enrollment_reports_keep_unknown_and_third_party_distinct_from_unenrolled() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/report-request-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for state in [
        "unenrolled",
        "this_organization",
        "other_organization",
        "unknown",
    ] {
        let value = json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":2,"observedAt":3,"collection":enrollment_collection(),"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":state}}}]}});
        let request: ReportRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), value);
        assert!(validator.is_valid(&value));
    }
    for state in ["offline", "absent", "permissionDenied"] {
        let value = json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":2,"observedAt":3,"collection":enrollment_collection(),"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":state}}}]}});
        assert!(serde_json::from_value::<ReportRequest>(value.clone()).is_err());
    }
}
#[test]
fn enrollment_schema_and_signing_agree_on_text_and_expiry_boundaries() {
    use rss_mdm_agent_wire::runtime::EnrollmentTaskSpec;
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-payload-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let tenant = Uuid::new_v4();
    let base = json!({"wireVersion":1,"tenantId":tenant,"deviceId":"agent","platform":"macos","architecture":"aarch64","registrationId":Uuid::new_v4(),"generation":1,"taskId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"permit":"offer","expiresAt":1,"organization":tenant,"entry":{"kind":"macos","url":"https://mdm.example.test/enroll"}});
    for (field, value, expected) in [
        ("expiresAt", json!(0), false),
        ("expiresAt", json!(1), true),
        ("deviceId", json!("a".repeat(256)), true),
        ("deviceId", json!("a".repeat(257)), false),
        ("deviceId", json!("界".repeat(256)), true),
        ("deviceId", json!("界".repeat(257)), false),
    ] {
        let mut value_json = base.clone();
        value_json[field] = value;
        let task: EnrollmentTaskSpec = serde_json::from_value(value_json.clone()).unwrap();
        assert_eq!(validator.is_valid(&value_json), expected, "schema: {field}");
        assert_eq!(
            task.signing_bytes("key").is_ok(),
            expected,
            "signing: {field}"
        );
    }
}

fn enrollment_collection() -> rss_mdm_agent_wire::runtime::CollectionDefinition {
    support::enrollment_collection()
}

#[test]
fn enrollment_task_rejects_the_old_signature_domain() {
    use base64::Engine;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use rss_mdm_agent_wire::runtime::*;
    let id = Uuid::new_v4();
    let spec: EnrollmentTaskSpec = serde_json::from_value(json!({"wireVersion":1,
        "tenantId":id,"deviceId":"agent","platform":"macos","architecture":"aarch64",
        "registrationId":id,"generation":1,"taskId":id,"attemptId":id,
        "permit":"offer","expiresAt":200,"organization":id,
        "entry":{"kind":"macos","url":"https://mdm.example.test/enroll"}}))
    .unwrap();
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let bytes = spec.signing_bytes("key").unwrap();
    let context = TaskVerification {
        key_id: "key",
        public_key: key.public_key().as_ref(),
        tenant_id: id,
        device_id: "agent",
        platform: TaskPlatform::Macos,
        architecture: TaskArchitecture::Aarch64,
        registration_id: id,
        generation: 1,
        task_id: id,
        attempt_id: id,
        permit: TaskPermit::Offer,
        now: 100,
    };
    let mut signed = SignedTask {
        payload: spec.try_into().unwrap(),
        key_id: "key".into(),
        signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(key.sign(&bytes).as_ref()),
    };
    signed.verify(&context).unwrap();
    let old_domain = b"rss-mdm-agent-mdm-enrollment-v6-ed25519\0";
    let current_domain = b"rss-mdm-agent-mdm-enrollment-v1-ed25519\0";
    assert!(bytes.starts_with(current_domain));
    let mut old_bytes = old_domain.to_vec();
    old_bytes.extend_from_slice(&bytes[current_domain.len()..]);
    signed.signature =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(&old_bytes).as_ref());
    assert!(signed.verify(&context).is_err());
}
