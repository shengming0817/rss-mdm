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
    let mut request = json!({"wireVersion":5,"operationId":Uuid::new_v4(),"enrollmentId":Uuid::new_v4(),"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","credential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","capabilities":["inventory.collect.v5"],"platform":"windows","architecture":"x86_64","executionContext":{"revision":1,"osVersion":[10,0,22621,0],"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false}});
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/registration-request-v5.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(serde_json::from_value::<RegistrationRequest>(request.clone()).is_ok());
    assert!(validator.is_valid(&request));
    request.as_object_mut().unwrap().remove("executionContext");
    assert!(serde_json::from_value::<RegistrationRequest>(request.clone()).is_err());
    assert!(!validator.is_valid(&request));
}
