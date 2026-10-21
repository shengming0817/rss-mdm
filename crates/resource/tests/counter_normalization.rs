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
