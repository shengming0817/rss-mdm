use super::*;
#[test]
fn summary_keeps_execution_evidence_and_strips_nested_output_streams() {
    use rss_mdm_agent_wire::runtime as w;
    let evidence = w::SoftwareTaskResult {
        intent: w::SoftwareTaskIntent::Install,
        definition_digest: [1; 32],
        steps: vec![w::SoftwareStepResult {
            step_id: [2; 32],
            index: 0,
            step_digest: [3; 32],
            target: w::SoftwareExecutionTarget::Device,
            package: "com.example.package".into(),
            identity: w::SoftwareObservedIdentity::PkgReceipt {
                receipt: "com.example.package".into(),
            },
            before: w::SoftwareDetectionObservation::Unknown {
                diagnostic: "unavailable".into(),
            },
            after: w::SoftwareDetectionObservation::Unknown {
                diagnostic: "unavailable".into(),
            },
            process: w::SoftwareProcessObservation::NotRun,
            reboot_required: false,
            diagnostics: w::TaskDiagnostics::new("canary".into(), "canary".into(), 23, 1, None)
                .unwrap(),
        }],
    };
    let value = serde_json::json!({
        "intent":"install", "definitionDigest":vec![1;32], "evidence":evidence,
        "effect":"unknown", "effectObservedAt":null, "effectReceivedAt":2,"receivedAt":2
    });
    let summary: SummaryResult = serde_json::from_value(value.clone()).unwrap();
    let projected = serde_json::to_value(summary).unwrap();
    assert_eq!(projected["effect"], "unknown");
    assert_eq!(
        projected["evidence"]["steps"][0]["diagnostics"],
        serde_json::json!({"durationMs":23,"executedAt":1,"failure":null})
    );
    assert!(!projected.to_string().contains("canary"));
    let mut unknown = value;
    unknown["evidence"]["steps"][0]["futureState"] = true.into();
    assert!(serde_json::from_value::<SummaryResult>(unknown).is_err());
}
