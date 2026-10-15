use rss_mdm_agent_wire::{CollectionScope, runtime as w};
use rss_mdm_resource::*;
fn spec(ty: w::CimType) -> AgentCollectionSpec {
    let budget = w::NativeBudget {
        timeout_seconds: 60,
        output_bytes: 4096,
        max_rows: 1,
    };
    AgentCollectionSpec {
        plan: w::NativeCollectionPlan::new(w::NativePlanSpec {
            version: 1,
            scope: CollectionScope::Device,
            budget,
            queries: [(
                "sample".into(),
                w::NativeQuery {
                    version: 1,
                    definition: w::NativeQueryDefinition::WindowsWmi {
                        namespace: "root\\acme".into(),
                        class: "Sensor".into(),
                        properties: [(
                            "Value".into(),
                            w::WmiProperty {
                                cim_type: ty,
                                array: false,
                            },
                        )]
                        .into(),
                        filter: None,
                    },
                    cardinality: w::NativeCardinality::ExactlyOne,
                    instance_keys: vec![],
                    budget,
                },
            )]
            .into(),
        })
        .unwrap(),
        mappings: [(
            "custom.temperature".into(),
            AgentCollectionMapping {
                query: "sample".into(),
                mapping: ValueMapping {
                    pointer: "/Value".into(),
                    conversion: Conversion::Number,
                    columns: Default::default(),
                },
                missing: NativeMissing::Missing,
            },
        )]
        .into(),
    }
}
#[test]
fn decimal_strings_can_be_converted_but_uint64_cannot_lose_precision() {
    AgentCollectionDefinition::new(spec(w::CimType::String)).unwrap();
    assert!(AgentCollectionDefinition::new(spec(w::CimType::Uint64)).is_err());
    assert_eq!(
        Conversion::Number
            .apply(&serde_json::json!("12.5"))
            .unwrap(),
        serde_json::json!(12.5)
    );
    assert!(Conversion::Number.apply(&serde_json::json!("NaN")).is_err());
}
#[test]
fn one_query_can_bind_multiple_fields_and_unknown_queries_are_rejected() {
    let mut spec = spec(w::CimType::String);
    spec.mappings.insert(
        "custom.other_temperature".into(),
        spec.mappings["custom.temperature"].clone(),
    );
    let definition = AgentCollectionDefinition::new(spec.clone()).unwrap();
    assert_eq!(definition.spec().plan.spec().queries.len(), 1);
    spec.mappings.get_mut("custom.temperature").unwrap().query = "missing".into();
    assert!(AgentCollectionDefinition::new(spec).is_err());
}

#[test]
fn macos_device_publication_is_platform_exact_and_scoped_recipes_are_rejected() {
    let blueprints::Definition::AgentCollection { template } =
        blueprints::get("macos.agent.receipts", "1")
            .unwrap()
            .definition
    else {
        unreachable!()
    };
    template.validate_platform(Platform::MacOS).unwrap();
    assert!(template.validate_platform(Platform::Windows).is_err());
    for definition in [
        w::NativeQueryDefinition::MacosApplications {
            root: w::MacosApplicationRoot::LocalApplications,
            max_depth: 2,
        },
        w::NativeQueryDefinition::MacosApplications {
            root: w::MacosApplicationRoot::UserApplications,
            max_depth: 2,
        },
        w::NativeQueryDefinition::MacosBrew {
            prefix: "/opt/homebrew".into(),
            package: w::MacosBrewPackage::Formula,
            taps: Default::default(),
        },
    ] {
        let mut spec = template.spec().clone();
        let mut plan = spec.plan.spec().clone();
        plan.queries.get_mut("receipts").unwrap().definition = definition;
        spec.plan = w::NativeCollectionPlan::new(plan).unwrap();
        assert!(AgentCollectionDefinition::new(spec).is_err());
    }
}
