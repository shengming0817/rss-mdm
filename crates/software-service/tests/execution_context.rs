use rss_mdm_agent_wire::runtime::*;
use rss_mdm_software_service::preparation::execution::*;
use serde_json::json;
use uuid::Uuid;
fn context() -> SoftwareExecutionContext {
    SoftwareExecutionContext {
        revision: 1,
        os_version: [10, 0, 22621, 0],
        user_helper: true,
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
    serde_json::from_value(json!({"package":"Acme.Editor","version":"2.0.0.0","reboot":"report","downgrade":"deny","signatures":[],"behavior":{"kind":"msix","container":{"kind":"package","installer":"package"},"identity":{"name":"Acme.Editor","publisher":"CN=Acme","version":[2,0,0,0],"architecture":"x86_64","resourceId":""},"dependencies":[],"deployment":if provisioning{json!({"kind":"device_provisioning"})}else{json!({"kind":"target_user_registration","target":{"kind":"active_interactive"}})},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":true,"uninstall":true,"invocation":{"runAs":if provisioning{"system"}else{"logged_in_user"},"arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}},"upgrade":"in_place"}})).unwrap()
}
#[test]
fn user_registration_binds_sid_and_login_while_provisioning_remains_device_scoped() {
    let live = context();
    let mut action = msix(false);
    let target = bind_target(&mut action, TaskPlatform::Windows, &live).unwrap();
    assert_eq!(
        target,
        SoftwareExecutionTarget::User {
            identity: live.interactive_user.as_ref().unwrap().identity.clone(),
            session_id: live.interactive_user.as_ref().unwrap().session_id
        }
    );
    let mut different = live.clone();
    different.interactive_user.as_mut().unwrap().identity = "S-1-5-21-1-2-3-1002".into();
    assert!(action_target(&action, TaskPlatform::Windows, &different).is_err());
    let mut unbound = live.clone();
    unbound.user_helper = false;
    assert!(action_target(&action, TaskPlatform::Windows, &unbound).is_err());
    assert!(
        identity_target(
            ExecutionIdentity::LoggedInUser,
            TaskPlatform::Windows,
            &unbound
        )
        .is_err()
    );
    assert_eq!(
        identity_target(ExecutionIdentity::System, TaskPlatform::Windows, &unbound).unwrap(),
        SoftwareExecutionTarget::Device
    );
    let mut absent = live.clone();
    absent.interactive_user = None;
    assert!(action_target(&action, TaskPlatform::Windows, &absent).is_err());
    let device = msix(true);
    assert_eq!(
        action_target(&device, TaskPlatform::Windows, &absent).unwrap(),
        SoftwareExecutionTarget::Device
    );
    absent.system_broker = false;
    assert!(action_target(&device, TaskPlatform::Windows, &absent).is_err());
    let mut older = live.clone();
    older.os_version = [10, 0, 17763, 0];
    assert!(action_target(&action, TaskPlatform::Windows, &older).is_err());
    let mut blocked = live;
    blocked.msix_sideload = false;
    assert!(action_target(&action, TaskPlatform::Windows, &blocked).is_err());
    assert!(action_target(&action, TaskPlatform::Macos, &blocked).is_err());
}
#[test]
fn brew_requires_a_non_root_interactive_account() {
    let invocation = json!({"runAs":"logged_in_user","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let action:SoftwareTaskAction=serde_json::from_value(json!({"package":"tool","version":"1","reboot":"report","downgrade":"deny","signatures":[],"behavior":{"kind":"brew","installer":"package","scope":"user","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"pkg_receipt","receipt":"com.acme.tool","version":"1"}}})).unwrap();
    let mut live = context();
    live.msix_sideload = false;
    live.msix_unsigned = false;
    for uid in ["501", "0", "000"] {
        live.interactive_user.as_mut().unwrap().identity = uid.into();
        assert_eq!(
            action_target(&action, TaskPlatform::Macos, &live).is_ok(),
            uid == "501"
        );
    }
}
#[test]
fn native_read_credentials_require_the_exact_source_and_reference_pair() {
    let export: SoftwareTaskExport = serde_json::from_value(json!({"kind":"brew",
        "binding":{"source":"enterprise","tenantId":Uuid::new_v4(),"ring":"pilot",
            "publication":vec![1;32],"sourceDigest":vec![2;32],"resource":"app","resourceVersion":"1",
            "resourceDigest":vec![3;32],"definitionDigest":vec![4;32],"documentSha256":vec![5;32],
            "dependencies":[],"artifacts":[{"url":"https://mdm.example.test/app","length":1,"sha256":vec![6;32]}]},
        "uri":"https://mdm.example.test/tap","commit":"a".repeat(40),"tap":"enterprise/app","credentialReference":"read-one"})).unwrap();
    let mut live = context();
    assert!(validate_export_context(&export, &live).is_err());
    for (source, reference, expected) in [
        ("enterprise", "read-one", true),
        ("other", "read-one", false),
        ("enterprise", "read-two", false),
    ] {
        live.source_credentials = vec![SoftwareReadCredential {
            source: source.into(),
            reference: reference.into(),
        }];
        assert_eq!(validate_export_context(&export, &live).is_ok(), expected);
    }
}
