use super::*;
use serde_json::{Value, json};
fn definition() -> Value {
    json!({"key":"employeeNumber","displayName":"Employee number","source":{"kind":"identity_local"},"pointer":"/extensions/employeeNumber","valueType":"string","maxLength":64,"maxItems":null,"minimum":null,"maximum":null,"enabled":true,"sensitive":false,"visibility":"both","displayUse":"profile","required":true,"useExistingObservation":false})
}

#[test]
fn mapping_types_and_pointers_reject_coercion_and_invalid_paths() {
    let mut d: DefinitionValue = serde_json::from_value(definition()).unwrap();
    for path in [
        "relative",
        "/extensions/~2bad",
        "/extensions/trailing~",
        "/extensions/\0",
    ] {
        d.pointer = path.into();
        assert!(model::validate(&d).is_err());
    }
    for path in ["", "/extensions/a~1b/~0key", "/extensions/"] {
        d.pointer = path.into();
        assert!(model::validate(&d).is_ok());
    }
    assert!(!model::conforms(&json!(42), &d));
    d.value_type = ValueType::Integer;
    d.max_length = None;
    assert!(model::conforms(&json!(9007199254740991_i64), &d));
    for value in [
        json!(9007199254740992_u64),
        json!(1.5),
        json!("42"),
        json!(true),
    ] {
        assert!(!model::conforms(&value, &d));
    }
    d.value_type = ValueType::Boolean;
    assert!(model::conforms(&json!(false), &d));
    assert!(!model::conforms(&json!(0), &d));
}
