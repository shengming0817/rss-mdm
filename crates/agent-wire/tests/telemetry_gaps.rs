use rss_mdm_agent_wire::runtime::*;
use serde_json::json;
fn report() -> TelemetryGapReport {
    TelemetryGapReport {
        report_id: uuid::Uuid::new_v4(),
        registration_id: uuid::Uuid::new_v4(),
        generation: 1,
        created_at: 1000000,
        gaps: vec![TelemetryGap {
            reason: TelemetryGapReason::Capacity,
            count: 2,
            first: 1,
            last: 2,
        }],
    }
}
#[test]
fn gap_report_has_bounded_closed_diagnostic_semantics() {
    let good = report();
    good.validate().unwrap();
    let value = serde_json::to_value(&good).unwrap();
    assert_eq!(
        serde_json::from_value::<TelemetryGapReport>(value.clone()).unwrap(),
        good
    );
    for change in 0..9 {
        let mut bad = good.clone();
        match change {
            0 => bad.gaps.clear(),
            1 => bad.gaps.push(bad.gaps[0].clone()),
            2 => bad.gaps[0].count = 0,
            3 => bad.gaps[0].count = u64::MAX,
            4 => bad.gaps[0].first = -1,
            5 => bad.gaps[0].last = 0,
            6 => bad.created_at = i64::MAX,
            7 => bad.generation = 0,
            _ => bad.report_id = uuid::Uuid::nil(),
        }
        assert!(bad.validate().is_err());
    }
    for key in ["tenantId", "deviceId", "source", "policy", "binding"] {
        let mut bad = value.clone();
        bad[key] = json!("forged");
        assert!(serde_json::from_value::<TelemetryGapReport>(bad).is_err());
    }
    let mut bad = value;
    bad["gaps"][0]["reason"] = json!("custom-text");
    assert!(serde_json::from_value::<TelemetryGapReport>(bad).is_err());
}
#[test]
fn gap_generated_schema_and_receipt_match_current_wire() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/telemetry-gap-report-v1.schema.json"
    ))
    .unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(report()).unwrap())
    );
    let receipt = TelemetryGapReceipt {
        report_id: uuid::Uuid::new_v4(),
        received_at: 123,
        replayed: true,
    };
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schema/runtime/telemetry-gap-receipt-v1.schema.json"
    ))
    .unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(receipt).unwrap())
    );
}
