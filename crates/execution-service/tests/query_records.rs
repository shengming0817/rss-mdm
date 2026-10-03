use super::*;
#[test]
fn summary_keeps_execution_evidence_and_strips_nested_output_streams() {
    let value = serde_json::json!({"effect":"unknown","output":{"secret":"canary"},"diagnostics":{"durationMs":23,"stdout":"canary","stderr":"canary"},"evidence":{"steps":[{"state":"failed","diagnostics":{"stdout":"canary","stderr":"canary","executedAt":1}}]}});
    let summary: SummaryResult = serde_json::from_value(value).unwrap();
    let value = serde_json::to_value(summary).unwrap();
    assert_eq!(value["effect"], "unknown");
    assert_eq!(value["diagnostics"]["durationMs"], 23);
    assert_eq!(value["evidence"]["steps"][0]["state"], "failed");
    assert_eq!(
        value["evidence"]["steps"][0]["diagnostics"]["executedAt"],
        1
    );
    assert!(!value.to_string().contains("canary"));
}
