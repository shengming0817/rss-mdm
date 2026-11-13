//! Current complete-report and telemetry capacities are independent of their byte budgets.
use rss_mdm_agent_wire::runtime::*;
use serde_json::json;
use std::collections::BTreeMap;
use uuid::Uuid;

fn field(index: usize, value_type: ValueType) -> FieldDefinition {
    serde_json::from_value(json!({
        "key":format!("custom.capacity.f{index:04}"),"version":1,"valueType":value_type,
        "nullable":false,"manual":false,"sources":{"agent.builtin":0},
        "platforms":["windows"],"sensitivity":"standard","unit":null,
        "searchable":false,"itemKey":null,"timeSeries":null
    }))
    .unwrap()
}

#[test]
fn complete_report_covers_4096_distinct_fields() {
    let fields = (0..4096)
        .map(|i| field(i, ValueType::Boolean))
        .collect::<Vec<_>>();
    let values = fields
        .iter()
        .map(|f| FieldValue {
            field: f.key,
            value: CollectedValue::Value(Scalar::Boolean(true)),
        })
        .collect();
    let definition =
        CollectionDefinition::new("capacity", 1, Source::AgentBuiltin, fields.clone()).unwrap();
    let report = ReportRequest::new(
        Uuid::new_v4(),
        1,
        1,
        definition,
        ReportBody::Snapshot(values),
    )
    .unwrap();
    let encoded = report.canonical().unwrap();
    assert!(encoded.len() <= MAX_REPORT_BYTES);
    let restored: ReportRequest = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored.values().len(), 4096);
    assert_eq!(restored.canonical().unwrap(), encoded);
    let mut oversized = fields;
    oversized.push(field(4096, ValueType::Boolean));
    assert!(CollectionDefinition::new("capacity", 1, Source::AgentBuiltin, oversized).is_err());
}

#[test]
fn structured_values_and_complete_report_have_separate_bounds() {
    let field = field(
        0,
        ValueType::Array {
            items: Box::new(ValueType::String {
                max_length: 65536,
                allow_empty: false,
            }),
            max_items: 100,
        },
    );
    let definition =
        CollectionDefinition::new("capacity", 1, Source::AgentBuiltin, vec![field.clone()])
            .unwrap();
    let make = |count| {
        ReportRequest::new(
            Uuid::new_v4(),
            1,
            1,
            definition.clone(),
            ReportBody::Snapshot(vec![FieldValue {
                field: field.key,
                value: CollectedValue::Value(Scalar::Array(vec![
                    Scalar::String(
                        "\\\"".repeat(20000)
                    );
                    count
                ])),
            }]),
        )
        .unwrap()
    };
    let large = make(2);
    assert!(serde_json::to_vec(&large.values()[0].value).unwrap().len() > 65536);
    assert!(large.canonical().unwrap().len() < MAX_REPORT_BYTES);
    assert!(make(64).canonical().is_err());
}

fn binding(dimensions: BTreeMap<String, TelemetryDimension>) -> TimeSeriesBinding {
    TimeSeriesBinding {
        kind: TelemetryKind::Gauge,
        value_path: vec!["value".into()],
        interval_start_path: None,
        dimensions,
        aggregations: [TelemetryAggregation::Min].into(),
        retention: RetentionReference {
            key: "retention".into(),
            revision: 1,
        },
        max_resources: 1,
    }
}

#[test]
fn telemetry_counts_preserve_vocabulary_and_expansion_budgets() {
    let mut value = binding(
        (0..1024)
            .map(|i| {
                (
                    format!("d{i:04}"),
                    TelemetryDimension {
                        path: vec!["state".into()],
                        values: ["v".into()].into(),
                    },
                )
            })
            .collect(),
    );
    value.validate().unwrap();
    value.dimensions.insert(
        "extra".into(),
        TelemetryDimension {
            path: vec!["state".into()],
            values: ["v".into()].into(),
        },
    );
    assert!(value.validate().is_err());

    let values = (0..1024).map(|i| format!("v{i:04}")).collect();
    let mut value = binding(
        [(
            "state".into(),
            TelemetryDimension {
                path: vec!["state".into()],
                values,
            },
        )]
        .into(),
    );
    value.validate().unwrap();
    value.max_resources = 8;
    assert!(value.validate().is_err());
    value.max_resources = 1;
    value.dimensions.get_mut("state").unwrap().values = (0..1024)
        .map(|i| format!("v{i:04}{}", "x".repeat(40)))
        .collect();
    assert!(value.validate().is_err());

    let state = ValueType::Enum {
        values: (0..1024).map(|i| format!("s{i:04}")).collect(),
    };
    state.validate().unwrap();
    let ValueType::Enum { mut values } = state else {
        unreachable!()
    };
    values.insert("extra".into());
    assert!(ValueType::Enum { values }.validate().is_err());
}
