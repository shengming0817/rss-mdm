use rss_mdm_agent_wire::runtime::ReportRequest;
use serde_json::json;
use uuid::Uuid;
#[test]
fn enrollment_reports_keep_unknown_and_third_party_distinct_from_unenrolled() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/report-request-v6.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for state in [
        "unenrolled",
        "this_organization",
        "other_organization",
        "unknown",
    ] {
        let value = json!({"wireVersion":6,"reportId":Uuid::new_v4(),"sequence":2,"observedAt":3,"collection":enrollment_collection(),"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":state}}}]}});
        let request: ReportRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), value);
        assert!(validator.is_valid(&value));
    }
    for state in ["offline", "absent", "permissionDenied"] {
        let value = json!({"wireVersion":6,"reportId":Uuid::new_v4(),"sequence":2,"observedAt":3,"collection":enrollment_collection(),"body":{"kind":"snapshot","values":[{"field":"channel.mdm.enrollment","value":{"kind":"value","value":{"kind":"string","value":state}}}]}});
        assert!(serde_json::from_value::<ReportRequest>(value.clone()).is_err());
    }
}
#[test]
fn enrollment_schema_and_signing_agree_on_text_and_expiry_boundaries() {
    use rss_mdm_agent_wire::runtime::EnrollmentTaskSpec;
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/task-payload-v6.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let tenant = Uuid::new_v4();
    let base = json!({"wireVersion":6,"tenantId":tenant,"deviceId":"agent","platform":"macos","architecture":"aarch64","registrationId":Uuid::new_v4(),"generation":1,"taskId":Uuid::new_v4(),"attemptId":Uuid::new_v4(),"permit":"offer","expiresAt":1,"organization":tenant,"entry":{"kind":"macos","url":"https://mdm.example.test/enroll"}});
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
    rss_mdm_agent_wire::runtime::CollectionDefinition::new(
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
