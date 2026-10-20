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
    let mut nodes = 0;
    value.iter().all(|(key, child)| {
        !key.is_empty()
            && key.len() <= 256
            && !key.chars().any(char::is_control)
            && visit(child, 1, &mut nodes)
    }) && serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= limit)
}
