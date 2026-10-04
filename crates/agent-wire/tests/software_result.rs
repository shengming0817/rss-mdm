use rss_mdm_agent_wire::runtime::*;
use serde_json::json;
#[test]
fn software_result_cannot_claim_a_global_detection_without_step_target_identity() {
    let old = json!({"intent":"install","installerExitCode":0,"detection":"present","definitionDigest":vec![1;32],"observedVersion":"1","evidenceDigest":vec![2;32],"rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}});
    assert!(serde_json::from_value::<SoftwareTaskResult>(old).is_err());
}
