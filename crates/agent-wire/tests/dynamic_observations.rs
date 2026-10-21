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
