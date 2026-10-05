use rss_mdm_agent_wire::runtime::*;
use uuid::Uuid;
#[test]
fn signed_user_targets_require_platform_identity_and_login_generation() {
    for (platform, identity, valid) in [
        (TaskPlatform::Windows, "S-1-5-21-1001", true),
        (TaskPlatform::Macos, "501", true),
        (TaskPlatform::Windows, "alice", false),
        (TaskPlatform::Macos, "alice", false),
        (TaskPlatform::Macos, "S-1-5-21-1001", false),
    ] {
        let target = SoftwareExecutionTarget::User {
            identity: identity.into(),
            session_id: Uuid::new_v4(),
        };
        assert_eq!(target.validate_for(platform).is_ok(), valid);
    }
    assert!(
        SoftwareExecutionTarget::User {
            identity: "501".into(),
            session_id: Uuid::nil()
        }
        .validate_for(TaskPlatform::Macos)
        .is_err()
    );
}
#[test]
fn context_schema_preserves_four_part_u16_os_versions() {
    let schema = serde_json::to_value(schemars::schema_for!(SoftwareExecutionContext)).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for (version, expected) in [
        (serde_json::json!([10, 0, 22621, 0]), true),
        (serde_json::json!([10, 0, 65535, 0]), true),
        (serde_json::json!([0, 0, 0, 0]), false),
        (serde_json::json!([10, 0, 65536, 0]), false),
        (serde_json::json!([10, 0, 1]), false),
        (serde_json::json!(vec![1; 32]), false),
    ] {
        let value = serde_json::json!({"revision":1,"msixSideload":false,"msixUnsigned":false,
            "osVersion":version,"systemBroker":true,"userHelper":false,"interactiveUser":null,"sourceCredentials":[]});
        assert_eq!(validator.is_valid(&value), expected, "{value}");
        let valid = serde_json::from_value::<SoftwareExecutionContext>(value)
            .is_ok_and(|context| context.validate().is_ok());
        assert_eq!(valid, expected);
    }
}
