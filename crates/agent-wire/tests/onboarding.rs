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
    let base = json!({"wireVersion":1,"tenantId":tenant,"deviceId":"agent","platform":"macos","architecture":"aarch64","registrationId":Uuid::new_v4(),"generation":1,"taskId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"permit":"offer","expiresAt":1,"organization":tenant,"authorization":{"kind":"policy","policyId":Uuid::new_v4(),"policyVersion":Uuid::new_v4()},"entry":{"kind":"macos","url":"https://mdm.example.test/enroll"}});
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
        assert_eq!(
            validator.is_valid(&json!({"kind":"enrollment","task":value_json})),
            expected,
            "schema: {field}"
        );
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
fn enrollment_authority_is_required_and_part_of_the_signature() {
    use rss_mdm_agent_wire::runtime::{EnrollmentTaskSpec, TaskPayload};
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/v1-vectors.json")).unwrap();
    let vector = vectors["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["family"] == "enrollment")
        .unwrap();
    let TaskPayload::Enrollment(task) =
        serde_json::from_str(vector["payloadJson"].as_str().unwrap()).unwrap()
    else {
        panic!("enrollment vector");
    };
    let original = task.signing_bytes("key").unwrap();
    let mut value = serde_json::to_value(&task).unwrap();
    value["authorization"]["policyVersion"] = json!(Uuid::new_v4());
    let changed: EnrollmentTaskSpec = serde_json::from_value(value.clone()).unwrap();
    assert_ne!(original, changed.signing_bytes("key").unwrap());
    value.as_object_mut().unwrap().remove("authorization");
    assert!(serde_json::from_value::<EnrollmentTaskSpec>(value).is_err());
}
