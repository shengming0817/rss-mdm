mod support;
use rss_mdm_agent_wire::runtime::*;
use serde_json::json;
use uuid::Uuid;

#[test]
fn unknown_fields_round_trip_and_participate_in_report_identity() {
    let id = Uuid::new_v4();
    let field = FieldKey::parse("custom.vendor_detail").unwrap();
    let make = |text: &str| {
        ReportRequest::new(
            id,
            1,
            1,
            support::collection(),
            ReportBody::Snapshot(vec![FieldValue {
                field,
                value: CollectedValue::Value(Scalar::String(text.into())),
            }]),
        )
        .unwrap()
    };
    let report = make("first");
    let bytes = report.canonical().unwrap();
    let restored: ReportRequest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.canonical().unwrap(), bytes);
    assert_ne!(bytes, make("changed").canonical().unwrap());
    assert!(restored.collection().field(field).is_err());
}

#[test]
fn object_projection_preserves_raw_attributes_but_validates_consumed_values() {
    let definition: FieldDefinition = serde_json::from_value(json!({
        "key":"custom.hardware", "version":1,
        "valueType":{"kind":"object","properties":{"id":{"kind":"string","maxLength":16,"allowEmpty":false}}},
        "nullable":false,"manual":false,"sources":{"agent.builtin":0},
        "platforms":["windows"],"sensitivity":"standard","unit":null,"searchable":false,"itemKey":null
    })).unwrap();
    let raw = CollectedValue::Value(Scalar::Object(
        [
            ("id".into(), Scalar::String("device".into())),
            (
                "vendor_note".into(),
                Scalar::String("retained evidence".into()),
            ),
        ]
        .into(),
    ));
    let projected = raw.project(&definition).unwrap();
    assert_ne!(projected, raw);
    assert!(projected.validate(&definition).is_ok());
    assert!(
        serde_json::to_value(&raw)
            .unwrap()
            .to_string()
            .contains("retained evidence")
    );
    for value in [
        Scalar::Object(Default::default()),
        Scalar::Object([("id".into(), Scalar::Boolean(true))].into()),
    ] {
        assert!(CollectedValue::Value(value).project(&definition).is_err());
    }
}

#[test]
fn record_projection_recurses_and_keeps_optional_members_optional() {
    let definition: FieldDefinition = serde_json::from_value(json!({
        "key":"custom.hardware", "version":1,
        "valueType":{"kind":"record","properties":{
            "items":{"required":true,"valueType":{"kind":"array","maxItems":2,"items":{
                "kind":"record","properties":{
                    "id":{"required":true,"valueType":{"kind":"string","maxLength":16,"allowEmpty":false}},
                    "note":{"required":false,"valueType":{"kind":"string","maxLength":16,"allowEmpty":true}}
                }
            }}},
            "optional":{"required":false,"valueType":{"kind":"integer"}}
        }},
        "nullable":false,"manual":false,"sources":{"agent.builtin":0},
        "platforms":["windows"],"sensitivity":"standard","unit":null,"searchable":false,"itemKey":null
    })).unwrap();
    let raw = CollectedValue::Value(Scalar::Object(
        [
            (
                "items".into(),
                Scalar::Array(vec![Scalar::Object(
                    [
                        ("id".into(), Scalar::String("device".into())),
                        ("vendor_note".into(), Scalar::Boolean(true)),
                    ]
                    .into(),
                )]),
            ),
            ("vendor_data".into(), Scalar::Integer(42)),
        ]
        .into(),
    ));
    let projected = raw.project(&definition).unwrap();
    assert_eq!(
        projected,
        CollectedValue::Value(Scalar::Object(
            [(
                "items".into(),
                Scalar::Array(vec![Scalar::Object(
                    [("id".into(), Scalar::String("device".into())),].into()
                )])
            ),]
            .into()
        ))
    );
    let collection = CollectionDefinition::new(
        "inventory",
        "1",
        Source::AgentBuiltin,
        vec![definition.clone()],
    )
    .unwrap();
    let report = ReportRequest::new(
        Uuid::new_v4(),
        1,
        1,
        collection,
        ReportBody::Snapshot(vec![FieldValue {
            field: definition.key,
            value: raw.clone(),
        }]),
    )
    .unwrap();
    let bytes = report.canonical().unwrap();
    let restored: ReportRequest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.canonical().unwrap(), bytes);
    assert!(String::from_utf8(bytes).unwrap().contains("vendor_note"));
    for item in [
        Scalar::Object(Default::default()),
        Scalar::Object([("id".into(), Scalar::Boolean(true))].into()),
        Scalar::Object(
            [
                ("id".into(), Scalar::String("device".into())),
                ("note".into(), Scalar::Integer(1)),
            ]
            .into(),
        ),
    ] {
        let invalid = CollectedValue::Value(Scalar::Object(
            [("items".into(), Scalar::Array(vec![item]))].into(),
        ));
        assert!(invalid.project(&definition).is_err());
    }
}
