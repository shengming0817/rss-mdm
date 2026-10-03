use rss_mdm_agent_wire::{enroll, runtime};
use serde_json::json;
use uuid::Uuid;
#[test]
fn http_versions_and_task_payload_versions_are_independent() {
    assert_eq!(enroll::API_VERSION, 1);
    assert_eq!(runtime::API_VERSION, 1);
    assert_eq!(runtime::PAYLOAD_VERSION, 6);
    let report = json!({"wireVersion":5,"reportId":Uuid::new_v4(),"sequence":1,"observedAt":1,"body":{"kind":"snapshot","values":[]}});
    assert!(serde_json::from_value::<runtime::ReportRequest>(report).is_err());
    let grant = json!({"wireVersion":6,"operationId":Uuid::new_v4(),"secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","platform":"macos"});
    assert!(serde_json::from_value::<enroll::GrantRequest>(grant).is_err());
}
