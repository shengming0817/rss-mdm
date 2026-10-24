//! Current management mapping contracts, derived from the actual HTTP carriers.
use schemars::{JsonSchema, generate::SchemaSettings};
use serde_json::{Value, json};
fn output<T: JsonSchema>() -> Value {
    serde_json::to_value(
        SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
            .into_root_schema_for::<T>(),
    )
    .unwrap()
}
fn schemas() -> Value {
    json!({
        "ResourceWrite": schemars::schema_for!(rss_mdm_flow_service::operation::Operation<rss_mdm_flow_service::resource_catalog::Change>),
        "ResourceResponse": output::<rss_mdm_flow_service::resource_catalog::wire::Response>(),
        "FieldWrite": schemars::schema_for!(rss_mdm_inventory_service::operation::Operation<rss_mdm_inventory_service::assets::FieldChange>),
        "FieldView": output::<rss_mdm_inventory_service::assets::FieldView>(),
        "FieldImpact": output::<rss_mdm_inventory_service::assets::FieldImpact>(),
        "FieldReferenceQuery": schemars::schema_for!(rss_mdm_inventory_service::assets::FieldReferenceQuery),
        "FieldMappingReference": output::<rss_mdm_inventory_service::assets::FieldMappingReference>(),
    })
}
#[cfg(not(test))]
fn main() {
    println!("{}", serde_json::to_string_pretty(&schemas()).unwrap());
}
#[test]
fn published_collection_contracts_match_http_types() {
    let expected: Value = serde_json::from_str(include_str!("../schema/Collection.json")).unwrap();
    assert_eq!(schemas(), expected);
}
