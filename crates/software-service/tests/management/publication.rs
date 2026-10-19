use crate::management::publication::model::Change;
use serde_json::json;
#[test]
fn publication_request_only_refers_to_an_exact_frozen_resource() {
    let current = json!({"action":"publish","target":"internal","targetDigest":vec![2;32],"resource":"acme","version":"1","resourceDigest":vec![1;32],"expectedResourceRevision":2});
    assert!(serde_json::from_value::<Change>(current.clone()).is_ok());
    let mut unknown = current.clone();
    unknown["unexpected"] = json!(true);
    assert!(serde_json::from_value::<Change>(unknown).is_err());
    let mut missing = current;
    missing.as_object_mut().unwrap().remove("resourceDigest");
    assert!(serde_json::from_value::<Change>(missing).is_err());
}
