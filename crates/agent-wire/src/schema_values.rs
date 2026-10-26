//! Schema shapes for existing validated scalars and explicitly owner-defined extension data.
use schemars::{Schema, SchemaGenerator, json_schema};

pub(crate) fn scalar_map(generator: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"object", "additionalProperties": crate::self_service::scalar_schema(generator)})
}
pub(crate) fn optional_scalar_map(generator: &mut SchemaGenerator) -> Schema {
    json_schema!({"anyOf":[scalar_map(generator), {"type":"null"}]})
}
pub(crate) fn native_scalar(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":["string", "boolean", "number"]})
}
pub(crate) fn enum_values(generator: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"object", "additionalProperties":native_scalar(generator)})
}
pub(crate) fn member_value(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":1, "maxLength":128, "pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]*$"})
}
pub(crate) fn presentation(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"object", "x-rss-extension":"Open presentation metadata; never authorization or execution input"})
}
pub(crate) fn schema_document(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":["object","boolean"], "x-rss-extension":"Self-contained JSON Schema document supplied by the Resource or capability owner"})
}
pub(crate) fn object_schema_document(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"object", "x-rss-extension":"Published object-form JSON Schema document validated by the collection owner"})
}
pub(crate) fn resource_output(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"x-rss-extension":"JSON output bound to the frozen Resource output schema and byte budget; trusted projections remain owner-validated"})
}
pub(crate) fn native_rows(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"array", "items":{"type":"object", "additionalProperties":{
        "x-rss-extension":"Native field value bound to the frozen queryDigest and query definition"
    }}})
}
