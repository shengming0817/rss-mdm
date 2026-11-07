//! Bounded descriptive data; this module grants no execution or read authority.
use serde_json::{Map, Value};
pub(crate) fn valid(value: &Map<String, Value>, limit: usize) -> bool {
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> bool {
        *nodes += 1;
        if depth > 16 || *nodes > 4096 {
            return false;
        }
        match value {
            Value::Object(values) => values.iter().all(|(key, child)| {
                !key.is_empty()
                    && key.len() <= 256
                    && !key.chars().any(char::is_control)
                    && visit(child, depth + 1, nodes)
            }),
            Value::Array(values) => values.iter().all(|child| visit(child, depth + 1, nodes)),
            Value::String(text) => !text.contains('\0'),
            _ => true,
        }
    }
    if serde_json::from_value::<Presentation>(Value::Object(value.clone())).is_err() {
        return false;
    }
    let mut nodes = 0;
    value.iter().all(|(key, child)| {
        !key.is_empty()
            && key.len() <= 256
            && !key.chars().any(char::is_control)
            && visit(child, 1, &mut nodes)
    }) && serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= limit)
}

/// Supported descriptive properties; arbitrary bounded extensions remain data, never query paths.
#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("additionalProperties" = {"x-rss-extension":"Bounded descriptive extensions; only typed properties are queryable"}))]
pub struct Presentation {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}
