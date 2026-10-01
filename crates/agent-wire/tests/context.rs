use rss_mdm_agent_wire::*;
use serde_json::json;
use uuid::Uuid;
fn context() -> SoftwareExecutionContext {
    SoftwareExecutionContext {
        revision: 1,
        os_version: [10, 0, 22621, 0],
        system_broker: true,
        interactive_user: Some(SoftwareInteractiveUser {
            identity: "S-1-5-21-1-2-3-1001".into(),
            session_id: Uuid::new_v4(),
            administrator: false,
        }),
        source_credentials: vec![],
        msix_sideload: true,
        msix_unsigned: true,
    }
}
fn msix(provisioning: bool) -> SoftwareTaskAction {
    serde_json::from_value(json!({"package":"Acme.Editor","version":"2.0.0.0","reboot":"report","downgrade":"deny","ownership":"managed_only","signatures":[],"behavior":{"kind":"msix","container":{"kind":"package","installer":"package"},"identity":{"name":"Acme.Editor","publisher":"CN=Acme","version":[2,0,0,0],"architecture":"x86_64","resourceId":""},"dependencies":[],"deployment":if provisioning{json!({"kind":"device_provisioning"})}else{json!({"kind":"target_user_registration","target":{"kind":"active_interactive"}})},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":true,"uninstall":true,"invocation":{"runAs":if provisioning{"system"}else{"logged_in_user"},"arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place"}})).unwrap()
}
#[test]
fn user_registration_binds_sid_and_login_while_provisioning_remains_device_scoped() {
    let live = context();
    let mut action = msix(false);
    let target = action
        .bind_execution_target(TaskPlatform::Windows, &live)
        .unwrap();
    assert_eq!(
        target,
        SoftwareExecutionTarget::User {
            identity: live.interactive_user.as_ref().unwrap().identity.clone(),
            session_id: live.interactive_user.as_ref().unwrap().session_id
        }
    );
    let mut different = live.clone();
    different.interactive_user.as_mut().unwrap().identity = "S-1-5-21-1-2-3-1002".into();
    assert!(
        action
            .execution_target(TaskPlatform::Windows, &different)
            .is_err()
    );
    let mut absent = live.clone();
    absent.interactive_user = None;
    assert!(
        action
            .execution_target(TaskPlatform::Windows, &absent)
            .is_err()
    );
    let device = msix(true);
    assert_eq!(
        device
            .execution_target(TaskPlatform::Windows, &absent)
            .unwrap(),
        SoftwareExecutionTarget::Device
    );
    absent.system_broker = false;
    assert!(
        device
            .execution_target(TaskPlatform::Windows, &absent)
            .is_err()
    );
    let mut older = live.clone();
    older.os_version = [10, 0, 17763, 0];
    assert!(
        action
            .execution_target(TaskPlatform::Windows, &older)
            .is_err()
    );
    let mut blocked = live;
    blocked.msix_sideload = false;
    assert!(
        action
            .execution_target(TaskPlatform::Windows, &blocked)
            .is_err()
    );
    assert!(
        action
            .execution_target(TaskPlatform::Macos, &blocked)
            .is_err()
    );
}
#[test]
fn context_updates_cannot_reuse_a_revision_or_restore_a_previous_login() {
    let first = context();
    let mut next = first.clone();
    next.revision = 2;
    next.interactive_user.as_mut().unwrap().session_id = Uuid::new_v4();
    assert!(next.validate_update(&first).is_ok());
    assert!(first.validate_update(&next).is_err());
    let mut reused = next.clone();
    reused.interactive_user.as_mut().unwrap().session_id = Uuid::new_v4();
    assert!(reused.validate_update(&next).is_err());
    assert!(next.validate_update(&next).is_ok());
}
