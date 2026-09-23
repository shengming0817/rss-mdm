use rss_mdm_agent_wire::{RegistrationRequest, ReportRequest, Secret, WIRE_VERSION};
use serde_json::json;
use uuid::Uuid;

#[test]
fn v2_replaces_v1_without_an_implicit_decode_path() {
    assert_eq!(WIRE_VERSION, 2);
    let secret = Secret::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let request =
        RegistrationRequest::new(Uuid::new_v4(), Uuid::new_v4(), secret.clone(), secret).unwrap();
    let mut value = serde_json::to_value(request).unwrap();
    value["wireVersion"] = json!(1);
    assert!(serde_json::from_value::<RegistrationRequest>(value).is_err());
    let report = json!({"wireVersion":1,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"body":{"kind":"snapshot","values":[]}});
    assert!(serde_json::from_value::<ReportRequest>(report).is_err());
}
