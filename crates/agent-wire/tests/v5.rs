use rss_mdm_agent_wire::{RegistrationRequest, ReportRequest, Secret, WIRE_VERSION};
use serde_json::json;
use uuid::Uuid;

#[test]
fn v5_rejects_the_previous_major_without_an_implicit_decode_path() {
    assert_eq!(WIRE_VERSION, 5);
    let secret = Secret::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let request = RegistrationRequest::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        secret.clone(),
        secret,
        vec![rss_mdm_agent_wire::Capability::InventoryCollectionV5],
        rss_mdm_agent_wire::TaskPlatform::Macos,
        rss_mdm_agent_wire::TaskArchitecture::Aarch64,
        rss_mdm_agent_wire::SoftwareExecutionContext {
            revision: 1,
            os_version: [14, 0, 0, 0],
            system_broker: true,
            interactive_user: None,
            source_credentials: vec![],
            msix_sideload: false,
            msix_unsigned: false,
        },
    )
    .unwrap();
    let mut value = serde_json::to_value(request).unwrap();
    value["wireVersion"] = json!(4);
    assert!(serde_json::from_value::<RegistrationRequest>(value).is_err());
    let report = json!({"wireVersion":4,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"body":{"kind":"snapshot","values":[]}});
    assert!(serde_json::from_value::<ReportRequest>(report).is_err());
}

#[test]
fn registration_requires_current_execution_context() {
    let request = json!({"wireVersion":4,"operationId":Uuid::new_v4(),"enrollmentId":Uuid::new_v4(),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","credential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","capabilities":["inventory.basic.v4"],"platform":"windows","architecture":"x86_64"});
    assert!(serde_json::from_value::<RegistrationRequest>(request).is_err());
}
