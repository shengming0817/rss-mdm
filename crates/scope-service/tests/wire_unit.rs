use super::*;
use crate::{ScopeChange, operation::Operation};
#[test]
fn request_fields_have_one_spelling_and_responses_are_typed() {
    let id = Uuid::new_v4();
    let valid =
        serde_json::json!({"operationId":id,"expectedRevision":1,"input":{"action":"delete"}});
    assert!(serde_json::from_value::<Operation<ScopeChange>>(valid.clone()).is_ok());
    let mut old = valid;
    old["operation_id"] = old["operationId"].take();
    assert!(serde_json::from_value::<Operation<ScopeChange>>(old).is_err());
    assert!(Response::decode(serde_json::json!({"invented":"untyped"})).is_err());
}

#[test]
fn preview_preserves_empty_limitations_and_recompute_is_a_distinct_action() {
    let definition = serde_json::json!({"targets":[],"limitations":null,"exclusions":[]});
    let mut value = serde_json::json!({"definition":definition,"channel":"mdm"});
    let unrestricted: crate::preview::Request = serde_json::from_value(value.clone()).unwrap();
    value["definition"]["limitations"] = serde_json::json!([]);
    let empty: crate::preview::Request = serde_json::from_value(value).unwrap();
    assert!(unrestricted.definition.limitations.is_none());
    assert_eq!(empty.definition.limitations, Some(Default::default()));
    let operation: Operation<ScopeChange> = serde_json::from_value(serde_json::json!({
        "operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"recompute"}
    }))
    .unwrap();
    assert!(matches!(operation.input, ScopeChange::Recompute));
}
