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
            .project_selected(
                json!({"reading":"42"}).pointer(&mapping.pointer).unwrap(),
                &ValueType::Integer
            )
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

#[test]
fn optional_record_projection_uses_frozen_presence_and_never_defaults_unknown_codes() {
    let ty = ValueType::Record {
        properties: [
            (
                "raw".into(),
                Property {
                    value_type: ValueType::Integer,
                    required: true,
                },
            ),
            (
                "known".into(),
                Property {
                    value_type: ValueType::Boolean,
                    required: false,
                },
            ),
        ]
        .into(),
    };
    let mapping = ValueMapping {
        pointer: "/rows".into(),
        conversion: Conversion::Identity,
        columns: [
            (
                "raw".into(),
                ValueMapping {
                    pointer: "/state".into(),
                    conversion: Conversion::Integer,
                    columns: Default::default(),
                },
            ),
            (
                "known".into(),
                ValueMapping {
                    pointer: "/known".into(),
                    conversion: Conversion::Enum {
                        values: [("0".into(), json!(false)), ("1".into(), json!(true))].into(),
                    },
                    columns: Default::default(),
                },
            ),
        ]
        .into(),
    };
    // Use exactly the metadata shape carried by frozen tasks and the management API.
    let (mapping, ty): (ValueMapping, ValueType) =
        serde_json::from_value(serde_json::to_value((&mapping, &ty)).unwrap()).unwrap();
    let raw = json!({"rows":[{"state":"2"}]});
    assert_eq!(
        mapping.project_selected(&raw["rows"][0], &ty).unwrap(),
        json!({"raw":2})
    );
    for (state, known) in [("0", false), ("1", true)] {
        assert_eq!(
            mapping
                .project_selected(&json!({"state":state,"known":state}), &ty)
                .unwrap(),
            json!({"raw":state.parse::<i64>().unwrap(),"known":known})
        );
    }
    for raw in [
        json!({"known":"1"}),
        json!({"state":"bad"}),
        json!({"state":"2","known":"2"}),
        json!({"state":"2","known":null}),
    ] {
        assert!(mapping.project_selected(&raw, &ty).is_err(), "{raw}");
    }
    let mut required = ty.clone();
    if let ValueType::Record { properties } = &mut required {
        properties.get_mut("known").unwrap().required = true;
    }
    assert!(
        mapping
            .project_selected(&json!({"state":"2"}), &required)
            .is_err()
    );
    let mut undeclared = mapping.clone();
    undeclared
        .columns
        .insert("extra".into(), ValueMapping::identity("/extra"));
    assert!(
        undeclared
            .project_selected(&json!({"state":"2","extra":true}), &ty)
            .is_err()
    );
}

#[test]
fn nested_records_keep_optional_absence_separate_from_explicit_null() {
    let ty = ValueType::Record {
        properties: [(
            "item".into(),
            Property {
                required: true,
                value_type: ValueType::Record {
                    properties: [(
                        "label".into(),
                        Property {
                            required: false,
                            value_type: ValueType::String {
                                max_length: 32,
                                allow_empty: true,
                            },
                        },
                    )]
                    .into(),
                },
            },
        )]
        .into(),
    };
    let mapping = ValueMapping {
        pointer: "".into(),
        conversion: Conversion::Identity,
        columns: [(
            "item".into(),
            ValueMapping {
                pointer: "/package".into(),
                conversion: Conversion::Identity,
                columns: [("label".into(), ValueMapping::identity("/label"))].into(),
            },
        )]
        .into(),
    };
    assert_eq!(
        mapping
            .project_selected(&json!({"package":{}}), &ty)
            .unwrap(),
        json!({"item":{}})
    );
    assert_eq!(
        mapping
            .project_selected(&json!({"package":{"label":null}}), &ty)
            .unwrap(),
        json!({"item":{"label":null}})
    );
    assert!(
        mapping
            .project_selected(&json!({"package":null}), &ty)
            .is_err()
    );
}
