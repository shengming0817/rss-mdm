use rss_mdm_agent_wire::{ManagedRegistrationRequest, ReportRequest};
use serde_json::json;
use uuid::Uuid;
#[test]
fn enrollment_reports_keep_unknown_and_third_party_distinct_from_unenrolled() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/report-request-v5.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for state in [
        "unenrolled",
        "this_organization",
        "other_organization",
        "unknown",
    ] {
        let value = json!({"wireVersion":5,"reportId":Uuid::new_v4(),"sequence":2,"observedAt":3,"collection":enrollment_collection(),"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":state}}}]}});
        let request: ReportRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), value);
        assert!(validator.is_valid(&value));
    }
    for state in ["offline", "absent", "permissionDenied"] {
        let value = json!({"wireVersion":5,"reportId":Uuid::new_v4(),"sequence":2,"observedAt":3,"collection":enrollment_collection(),"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":state}}}]}});
        assert!(serde_json::from_value::<ReportRequest>(value.clone()).is_err());
    }
}
#[test]
fn managed_registration_has_no_device_identity_or_bearer_claim() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/managed-registration-request-v5.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let value = json!({"wireVersion":5,"operationId":Uuid::new_v4(),"installationOperation":Uuid::new_v4(),"credential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","capabilities":["inventory.collect.v5"],"platform":"windows","architecture":"x86_64","executionContext":{"revision":1,"osVersion":[10,0,22621,0],"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false}});
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
    invalid["capabilities"] = json!(["inventory.collect.v5", "inventory.collect.v5"]);
    assert!(serde_json::from_value::<ManagedRegistrationRequest>(invalid).is_err());
}

#[test]
fn enrollment_schema_and_signing_agree_on_text_and_expiry_boundaries() {
    use rss_mdm_agent_wire::EnrollmentTaskSpec;
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schema/task-payload-v5.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let tenant = Uuid::new_v4();
    let base = json!({"wireVersion":5,"tenantId":tenant,"deviceId":"agent","platform":"macos","architecture":"aarch64","registrationId":Uuid::new_v4(),"generation":1,"taskId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"permit":"offer","expiresAt":1,"organization":tenant,"entry":{"kind":"macos","url":"https://mdm.example.test/enroll"}});
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

fn enrollment_collection() -> rss_mdm_agent_wire::CollectionDefinition {
    rss_mdm_agent_wire::CollectionDefinition::new(
        "channel.mdm.enrollment",
        1,
        rss_mdm_inventory::Source::AgentBuiltin,
        rss_mdm_inventory::builtin::fields()
            .into_iter()
            .filter(|f| f.key == rss_mdm_inventory::builtin::MDM_ENROLLMENT)
            .collect(),
    )
    .unwrap()
}
