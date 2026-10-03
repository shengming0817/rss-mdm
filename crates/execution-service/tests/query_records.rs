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

#[test]
fn native_declaration_details_preserve_typed_status_and_manifest() {
    let input = serde_json::json!({"protocol":"mdm.apple","observationScope":"declarations","progress":"received","effect":"unverified","compliance":"unknown","inputVersion":"v1","synchronization":"published","expected":{"Configurations":[]},"nativeStatus":{"items":{},"unknownItems":[],"declarations":[],"errors":[],"completeness":"unknown","effect":"unverified","synchronized":false,"compliance":"unknown"}});
    let record: NativeObservation = serde_json::from_value(input.clone()).unwrap();
    assert_eq!(serde_json::to_value(record).unwrap(), input);
}
