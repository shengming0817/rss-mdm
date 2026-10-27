use rss_mdm_query::directory::{Field, Kind, Projection, Schema};
use schemars::{JsonSchema, generate::SchemaSettings};
use serde::Serialize;

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct Row {
    id: String,
    custom_event: Option<String>,
    nested: Nested,
}
#[derive(Serialize, JsonSchema)]
struct Nested {
    required: bool,
}
static DIRECTORY: Schema = Schema {
    id: "projection",
    keys: &["id"],
    default_limit: 10,
    max_limit: 10,
    fields: &[
        Field::scalar("id", Kind::Text),
        Field::scalar("customEvent", Kind::Text),
        Field::output("nested"),
    ],
};

#[test]
fn selected_null_is_retained_while_unselected_fields_are_absent() {
    let query = DIRECTORY.parse("fields=customEvent").unwrap();
    let projected = query
        .project_typed(Row {
            id: "p".into(),
            custom_event: None,
            nested: Nested { required: true },
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(projected).unwrap(),
        serde_json::json!({"customEvent":null})
    );
    let schema = SchemaSettings::draft2020_12()
        .for_serialize()
        .into_generator()
        .into_root_schema_for::<Projection<Row>>()
        .to_value();
    assert!(schema.get("required").is_none());
    assert_eq!(
        schema["properties"]["customEvent"]["type"],
        serde_json::json!(["string", "null"])
    );
    // Projection changes only the selected row keys, not nested object requirements.
    assert_eq!(
        schema["$defs"]["Nested"]["required"],
        serde_json::json!(["required"])
    );
}

#[derive(Serialize, JsonSchema)]
struct TaggedRow {
    id: String,
    #[serde(flatten)]
    record: Record,
}
#[derive(Serialize, JsonSchema)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum Record {
    First(Nested),
    Second(String),
}
#[test]
fn flattened_discriminator_can_be_omitted_without_opening_nested_values() {
    let schema = SchemaSettings::draft2020_12()
        .for_serialize()
        .into_generator()
        .into_root_schema_for::<Projection<TaggedRow>>()
        .to_value();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for fields in [
        vec!["id"],
        vec!["kind"],
        vec!["value"],
        vec!["kind", "value"],
    ] {
        let row = Projection::select(
            TaggedRow {
                id: "r".into(),
                record: Record::First(Nested { required: true }),
            },
            fields,
        )
        .unwrap();
        let value = serde_json::to_value(row).unwrap();
        assert!(validator.is_valid(&value), "{value}: {schema}");
    }
    assert!(!validator.is_valid(&serde_json::json!({"kind":"first","value":{}})));
    assert!(!validator.is_valid(&serde_json::json!({"kind":"future"})));
    assert!(
        Projection::select(
            TaggedRow {
                id: "r".into(),
                record: Record::Second("v".into())
            },
            ["missing"]
        )
        .is_err()
    );
}
