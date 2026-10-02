use super::*;
use serde_json::json;
fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("11111111-2222-4333-8444-555555555555").unwrap()
}
fn protector() -> rss_mdm_native_protection::Protector {
    rss_mdm_native_protection::Protector::new(&[27; 32]).unwrap()
}
fn request() -> Create {
    serde_json::from_value(json!({"operationId":"11111111-1111-4111-8111-111111111111","inputVersion":"resource-1","target":{"kind":"device"},"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./DevInfo/Mod","instance":[],"operation":"get","value":null}}},"deadline":100})).unwrap()
}
#[test]
fn native_envelope_requires_input_version_and_explicit_target() {
    let new = serde_json::to_value(request()).unwrap();
    for key in ["inputVersion", "target"] {
        let mut missing = new.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<Create>(missing).is_err());
    }
    let old = json!({"operationId":Uuid::new_v4(),"task":{"kind":"profile_install","enabled":true},"deadline":100});
    assert!(serde_json::from_value::<Create>(old).is_err());
}
#[test]
fn input_digest_binds_tenant_device_user_and_version() {
    let mut input = request();
    let digest = input.digest(&protector(), tenant(), "device").unwrap();
    assert_ne!(
        digest,
        input
            .digest(
                &protector(),
                rss_request_context::TenantId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
                    .unwrap(),
                "device"
            )
            .unwrap()
    );
    assert_ne!(
        digest,
        input.digest(&protector(), tenant(), "other").unwrap()
    );
    input.target = NativeTarget::User {
        user_id: "native-user".into(),
    };
    assert_ne!(
        digest,
        input.digest(&protector(), tenant(), "device").unwrap()
    );
    input.target = NativeTarget::Device;
    input.input_version = "resource-2".into();
    assert_ne!(
        digest,
        input.digest(&protector(), tenant(), "device").unwrap()
    );
}
#[test]
fn native_deadlines_and_request_identity_remain_bounded() {
    let mut input = request();
    assert!(input.validate(99).is_ok());
    assert!(input.validate(100).is_err());
    input.deadline = i64::MAX;
    assert!(input.validate(1).is_err());
    input.deadline = 100;
    input.operation_id = Uuid::nil();
    assert!(input.validate(1).is_err());
    let mut value = serde_json::to_value(request()).unwrap();
    value["tenant"] = json!("untrusted");
    assert!(serde_json::from_value::<Create>(value).is_err());
}
#[test]
fn dispatch_v3_matches_its_native_wire_without_old_payload_fallback() {
    let validator = jsonschema::validator_for(
        &serde_json::from_str(include_str!("../../src/execution/dispatch-v3.json")).unwrap(),
    )
    .unwrap();
    let wire = serde_json::to_value(DispatchV3 {
        device: "device".into(),
        operation_id: request().operation_id,
        generation: 2,
        epoch: 3,
    })
    .unwrap();
    assert!(
        wire.get("request").is_none(),
        "native input must remain with the operation owner, not in Outbox"
    );
    assert!(validator.is_valid(&wire));
    assert!(serde_json::from_value::<DispatchV3>(wire.clone()).is_ok());
    let mut unknown = wire.clone();
    unknown["request"] = serde_json::to_value(request()).unwrap();
    assert!(!validator.is_valid(&unknown));
    assert!(serde_json::from_value::<DispatchV3>(unknown).is_err());
    let mut invalid = wire;
    invalid["operationId"] = json!(3);
    assert!(!validator.is_valid(&invalid));
    assert!(serde_json::from_value::<DispatchV3>(invalid).is_err());
}
#[test]
fn atomic_children_require_each_real_operation_permission() {
    let input:Create=serde_json::from_value(json!({"operationId":Uuid::new_v4(),"inputVersion":"1","target":{"kind":"device"},"deadline":100,"task":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"sequence","operations":[{"kind":"node","node":"./DevInfo/Mod","instance":[],"operation":"get","value":null},{"kind":"node","node":"./Device/Vendor/MSFT/RemoteWipe/doWipe","instance":[],"operation":"exec","value":null}]}}}})).unwrap();
    let permissions = input.task.permissions().unwrap();
    assert!(permissions.contains(&crate::authorization::Permission::InventoryCollect));
    assert!(permissions.contains(&crate::authorization::Permission::DeviceWipe));
}
#[test]
fn native_admission_rejects_unknown_objects_and_cross_scope_inputs() {
    let mut input = request();
    input.target = NativeTarget::User {
        user_id: "user-1".into(),
    };
    assert!(
        input.validate(1).is_err(),
        "a device URI cannot execute in a user envelope"
    );
    input.target = NativeTarget::Device;
    let Task::Windows {
        request: rss_mdm_windows_mdm::native::Execution::SyncMl { request: native },
    } = &mut input.task
    else {
        panic!("fixture")
    };
    let rss_mdm_windows_mdm::native::Request::Node { node, .. } = native else {
        panic!("fixture")
    };
    *node = "./Vendor/Invented/Property".into();
    assert!(
        input.validate(1).is_err(),
        "unknown objects must not poison a device's queue"
    );
}
#[test]
fn configuration_cannot_withdraw_a_different_native_object_or_claim_a_query() {
    let make = |uri: &str, operation: &str| json!({"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":uri,"instance":[],"operation":operation,"value":null}}});
    let a = "./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana";
    let b = "./Device/Vendor/MSFT/Policy/Config/Privacy/LetAppsAccessCamera";
    let invalid: crate::planning::configuration::Configuration = serde_json::from_value(
        json!({"target":{"kind":"device"},"apply":make(a,"delete"),"remove":make(b,"delete")}),
    )
    .unwrap();
    assert!(
        invalid.validate().is_err(),
        "withdrawal must not touch another owner's object"
    );
    let query: crate::planning::configuration::Configuration = serde_json::from_value(
        json!({"target":{"kind":"device"},"apply":make(a,"get"),"remove":null}),
    )
    .unwrap();
    assert!(
        query.validate().is_err(),
        "reading state does not confer configuration ownership"
    );
}
#[test]
fn native_configuration_is_not_a_software_admission_bypass() {
    let input:crate::planning::configuration::Configuration=serde_json::from_value(json!({"target":{"kind":"device"},"apply":{"platform":"windows","request":{"kind":"sync_ml","request":{"kind":"node","node":"./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/*/DownloadInstall","instance":["{11111111-1111-4111-8111-111111111111}"],"operation":"add","value":{"type":"xml","value":"<MsiInstallJob/>"}}}},"remove":null})).unwrap();
    assert!(input.validate().is_err());
}

#[test]
fn native_input_digest_is_not_a_keyless_pin_verifier() {
    use sha2::{Digest, Sha256};
    let mut input = request();
    input.task = serde_json::from_value(json!({"platform":"macos","request":{"kind":"command","command":{"requestType":"DeviceLock","fields":{"PIN":{"type":"string","value":"1234"}}}}})).unwrap();
    let canonical = serde_json::to_vec(&(
        "mdm.native-input/v3",
        tenant().to_string(),
        "device",
        &input.input_version,
        &input.target,
        &input.task,
    ))
    .unwrap();
    let guess = rss_device_command::StateDigest::from_bytes(Sha256::digest(canonical).into());
    assert_ne!(
        input.digest(&protector(), tenant(), "device").unwrap(),
        guess
    );
}
