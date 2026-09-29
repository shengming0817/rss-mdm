use super::*;
#[test]
fn request_fields_have_one_spelling_and_responses_are_typed() {
    let id = Uuid::new_v4();
    let valid =
        serde_json::json!({"operationId":id,"expectedRevision":1,"input":{"action":"delete"}});
    assert!(serde_json::from_value::<Operation<ScopeChange>>(valid.clone()).is_ok());
    let mut old = valid;
    old["operation_id"] = old["operationId"].take();
    assert!(serde_json::from_value::<Operation<ScopeChange>>(old).is_err());
    let request =
        serde_json::json!({"action":"approve","ring":"test","publisher_subject":"operator"});
    assert!(serde_json::from_value::<crate::software_publication::model::Change>(request).is_err());
    assert!(Response::decode(serde_json::json!({"invented":"untyped"})).is_err());
}
