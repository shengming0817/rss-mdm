//! Frozen projection admission is independent of query/execution authority.
use rss_mdm_agent_wire::runtime::*;
use serde_json::{Value, json};

fn task() -> CollectionTaskSpec {
    let v: Value = serde_json::from_str(include_str!("fixtures/native-v1-vectors.json")).unwrap();
    let TaskPayload::Collection(task) =
        serde_json::from_str(v[0]["tasks"][0]["payloadJson"].as_str().unwrap()).unwrap()
    else {
        panic!("native vector")
    };
    *task
}
#[test]
fn frozen_native_mapping_requires_exact_fields_queries_types_and_source() {
    let original = task();
    original.validate().unwrap();
    for change in 0..8 {
        let mut t = original.clone();
        let key = t.fields[0].key.as_str().to_owned();
        match change {
            0 => {
                t.mappings.clear();
            }
            1 => {
                t.mappings
                    .insert("custom.unselected".into(), t.mappings[&key].clone());
            }
            2 => t.mappings.get_mut(&key).unwrap().query = "unknown".into(),
            3 => {
                t.fields[0].value_type = ValueType::Boolean;
                t.mappings.get_mut(&key).unwrap().mapping.conversion = Conversion::Integer;
            }
            4 => {
                t.mappings.get_mut(&key).unwrap().counter_normalization =
                    Some(NativeCounterNormalization::LocalCumulativeV1)
            }
            5 => t.mappings.get_mut(&key).unwrap().missing = NativeMissing::Null,
            6 => {
                t.fields[0].sources.clear();
            }
            _ => t.fields.push(t.fields[0].clone()),
        }
        assert!(t.validate().is_err(), "mutation {change}");
    }
    let mut omitted = serde_json::to_value(original).unwrap();
    omitted.as_object_mut().unwrap().remove("mappings");
    assert!(serde_json::from_value::<CollectionTaskSpec>(omitted).is_err());
}
#[test]
fn custom_script_mapping_is_data_driven_and_none_is_explicit() {
    let mut field = task().fields.remove(0);
    field.key = FieldKey::parse("custom.new_sensor").unwrap();
    field.value_type = ValueType::Integer;
    field.platforms = [Platform::Macos].into();
    field.sources = [(Source::AgentScript, 0)].into();
    let mapping = ValueMapping {
        pointer: "/reading".into(),
        conversion: Conversion::Integer,
        columns: Default::default(),
    };
    let projection = ScriptProjection::Collection {
        fields: vec![field],
        mappings: [("custom.new_sensor".into(), mapping.clone())].into(),
        output_schema: json!({"type":"object","properties":{"reading":{"type":"string"}},"required":["reading"],"additionalProperties":false}),
        scope: rss_mdm_agent_wire::CollectionScope::Device,
    };
    projection
        .validate(ExecutorProfile::PosixSh, TaskPlatform::Macos)
        .unwrap();
    assert_eq!(
        mapping
            .project_selected(json!({"reading":"42"}).pointer(&mapping.pointer).unwrap())
            .unwrap(),
        json!(42)
    );
    assert!(
        projection
            .validate(ExecutorProfile::Osquery, TaskPlatform::Macos)
            .is_err()
    );
    assert!(
        projection
            .validate(ExecutorProfile::PosixSh, TaskPlatform::Windows)
            .is_err()
    );
    assert!(serde_json::from_value::<ScriptProjection>(json!({})).is_err());
    ScriptProjection::None
        .validate(ExecutorProfile::PosixSh, TaskPlatform::Macos)
        .unwrap();
}
#[test]
fn projection_budget_and_unknown_conversion_fail_before_interpretation() {
    let mut t = task();
    let field = &mut t.fields[0];
    field.value_type = ValueType::Enum {
        values: (0..128)
            .map(|i| format!("{i:03}{}", "a".repeat(250)))
            .collect(),
    };
    let mapping = t.mappings.values_mut().next().unwrap();
    mapping.mapping.conversion = Conversion::Enum {
        values: (0..128)
            .map(|i| (i.to_string(), json!(format!("{i:03}{}", "a".repeat(250)))))
            .collect(),
    };
    assert!(t.validate().is_err());
    assert!(
        serde_json::from_value::<ValueMapping>(
            json!({"pointer":"/x","conversion":{"kind":"shell"},"columns":{}})
        )
        .is_err()
    );
}
