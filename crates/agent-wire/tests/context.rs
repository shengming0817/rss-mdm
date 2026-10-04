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
