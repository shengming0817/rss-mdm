//! Local counter normalization is an explicit Network-only recipe, not a generic conversion.
use rss_mdm_agent_wire::{CollectionScope, runtime as w};
use rss_mdm_resource::*;

fn spec() -> AgentCollectionSpec {
    let budget = w::NativeBudget {
        timeout_seconds: 1,
        output_bytes: 4096,
        max_rows: 4,
    };
    AgentCollectionSpec {
        applicability: Default::default(),
        plan: w::NativeCollectionPlan::new(w::NativePlanSpec {
            version: 1,
            scope: CollectionScope::Device,
            budget,
            queries: [(
                "network".into(),
                w::NativeQuery {
                    version: 1,
                    definition: w::NativeQueryDefinition::MacosPerformance {
                        section: w::PerformanceSection::Network,
                    },
                    cardinality: w::NativeCardinality::List,
                    instance_keys: vec!["id".into()],
                    budget,
                },
            )]
            .into(),
        })
        .unwrap(),
        mappings: [(
            "custom.network.received".into(),
            AgentCollectionMapping {
                query: "network".into(),
                missing: NativeMissing::Missing,
                counter_normalization: Some(w::NativeCounterNormalization::LocalCumulativeV1),
                mapping: ValueMapping {
                    pointer: String::new(),
                    conversion: Conversion::Identity,
                    columns: [
                        ("id".into(), column("/id", Conversion::Identity)),
                        (
                            "received".into(),
                            column("/received_bytes", Conversion::Integer),
                        ),
                    ]
                    .into(),
                },
            },
        )]
        .into(),
    }
}
fn column(pointer: &str, conversion: Conversion) -> ValueMapping {
    ValueMapping {
        pointer: pointer.into(),
        conversion,
        columns: Default::default(),
    }
}

#[test]
fn normalization_roundtrips_only_for_network_recipe() {
    let valid = AgentCollectionDefinition::new(spec()).unwrap();
    let restored: AgentCollectionDefinition = serde_json::from_slice(&valid.canonical()).unwrap();
    assert_eq!(restored, valid);
    assert_eq!(
        restored.spec().mappings["custom.network.received"].counter_normalization,
        Some(w::NativeCounterNormalization::LocalCumulativeV1)
    );
    let mut invalid = spec();
    let mut plan = invalid.plan.spec().clone();
    plan.queries.get_mut("network").unwrap().definition =
        w::NativeQueryDefinition::MacosPerformance {
            section: w::PerformanceSection::FileSystems,
        };
    invalid.plan = w::NativeCollectionPlan::new(plan).unwrap();
    invalid
        .mappings
        .get_mut("custom.network.received")
        .unwrap()
        .mapping
        .columns
        .get_mut("received")
        .unwrap()
        .pointer = "/total_bytes".into();
    assert!(AgentCollectionDefinition::new(invalid.clone()).is_err());
    invalid
        .mappings
        .get_mut("custom.network.received")
        .unwrap()
        .counter_normalization = None;
    assert!(
        AgentCollectionDefinition::new(invalid).is_ok(),
        "unmarked filesystem remains a valid recipe"
    );
}

#[test]
fn field_semantics_require_explicit_normalization_and_a_distinct_generated_start() {
    let input = spec();
    let mapping = &input.mappings["custom.network.received"];
    let mapping = w::TelemetryNativeMapping {
        query: mapping.query.clone(),
        counter_normalization: mapping.counter_normalization,
        mapping: serde_json::from_value(serde_json::to_value(&mapping.mapping).unwrap()).unwrap(),
    };
    let query = &input.plan.spec().queries["network"].definition;
    let field = w::FieldDefinition {
        key: w::FieldKey::parse("custom.network.received").unwrap(),
        version: 1,
        value_type: w::ValueType::Array {
            max_items: 4,
            items: Box::new(w::ValueType::Object {
                properties: [
                    (
                        "id".into(),
                        w::ValueType::String {
                            max_length: 128,
                            allow_empty: false,
                        },
                    ),
                    ("received".into(), w::ValueType::Integer),
                    ("interval_start".into(), w::ValueType::Integer),
                ]
                .into(),
            }),
        },
        nullable: false,
        manual: false,
        sources: [(w::Source::AgentNative, 0)].into(),
        platforms: [w::Platform::Macos].into(),
        sensitivity: w::Sensitivity::Standard,
        unit: Some("bytes".into()),
        searchable: false,
        item_key: Some("id".into()),
        time_series: Some(w::TimeSeriesBinding {
            kind: w::TelemetryKind::CumulativeCounter,
            value_path: vec!["received".into()],
            interval_start_path: Some(vec!["interval_start".into()]),
            dimensions: Default::default(),
            aggregations: [w::TelemetryAggregation::Increase].into(),
            retention: w::RetentionReference {
                key: "standard".into(),
                revision: 1,
            },
            max_resources: 4,
        }),
    };
    mapping
        .validate_counter_normalization(query, &field)
        .unwrap();
    // Supply every field column through a valid native source conversion. Older
    // structural mapping validation accepted this shape, but bytes are not a timestamp.
    let mut unmarked = mapping.clone();
    unmarked.counter_normalization = None;
    unmarked.mapping.columns.insert(
        "interval_start".into(),
        w::TelemetryValueMapping {
            pointer: "/sent_bytes".into(),
            conversion: w::TelemetryConversion::Integer,
            columns: Default::default(),
        },
    );
    let mut complete = input.clone();
    let complete_mapping = complete
        .mappings
        .get_mut("custom.network.received")
        .unwrap();
    complete_mapping.counter_normalization = None;
    complete_mapping.mapping.columns.insert(
        "interval_start".into(),
        column("/sent_bytes", Conversion::Integer),
    );
    AgentCollectionDefinition::new(complete).unwrap();
    assert!(
        unmarked
            .validate_counter_normalization(query, &field)
            .is_err()
    );
    let mut invalid = field.clone();
    invalid.time_series.as_mut().unwrap().kind = w::TelemetryKind::Gauge;
    invalid.time_series.as_mut().unwrap().aggregations = [w::TelemetryAggregation::Mean].into();
    assert!(
        mapping
            .validate_counter_normalization(query, &invalid)
            .is_err()
    );
    invalid = field;
    invalid.time_series.as_mut().unwrap().interval_start_path = Some(vec!["received".into()]);
    assert!(
        mapping
            .validate_counter_normalization(query, &invalid)
            .is_err()
    );
}
