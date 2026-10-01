use crate::software_publication::model::Change;
use serde_json::json;
#[test]
fn publication_request_only_refers_to_an_exact_frozen_resource() {
    let current = json!({"action":"candidate","resource":"acme","version":"1","resourceDigest":vec![1;32],"expectedResourceRevision":2});
    assert!(serde_json::from_value::<Change>(current.clone()).is_ok());
    for name in ["submission", "document"] {
        let mut value = current.clone();
        value[name] = json!({"kind":"Winget","manifest":{}});
        assert!(serde_json::from_value::<Change>(value).is_err());
    }
    let mut missing = current;
    missing.as_object_mut().unwrap().remove("resourceDigest");
    assert!(serde_json::from_value::<Change>(missing).is_err());
}
