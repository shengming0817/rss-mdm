use super::case::{CaseContext, Phase};
fn planned() -> serde_json::Value {
    serde_json::json!({"caseId":"case", "invocationId":"invoke", "namespace":"00000000000000000000000000000001",
        "tenant":"11111111-1111-4111-8111-111111111111", "peer":"22222222-2222-4222-8222-222222222222",
        "actors":[{"tenant":"11111111-1111-4111-8111-111111111111", "role":"admin", "login":"admin-1", "principal":null}],
        "fixtures":["identity"]})
}
#[test]
fn rejects_malformed_and_incomplete_contract_before_consumption() {
    for field in [
        "caseId",
        "invocationId",
        "namespace",
        "tenant",
        "peer",
        "actors",
        "fixtures",
    ] {
        for replacement in [
            None,
            Some(serde_json::json!(42)),
            Some(serde_json::json!("")),
        ] {
            let mut value = planned();
            if let Some(replacement) = replacement {
                value[field] = replacement;
            } else {
                value.as_object_mut().unwrap().remove(field);
            }
            assert!(
                CaseContext::decode(&serde_json::to_vec(&value).unwrap(), Phase::Preparing)
                    .is_err(),
                "{field}"
            );
        }
    }
    let bytes = serde_json::to_vec(&planned()).unwrap();
    assert!(CaseContext::decode(&bytes, Phase::Preparing).is_ok());
    assert!(CaseContext::decode(&bytes, Phase::Ready).is_err());
    let mut value = CaseContext::decode(&bytes, Phase::Preparing).unwrap();
    value.actors_mut()[0].principal = Some("44444444-4444-4444-8444-444444444444".into());
    assert!(CaseContext::decode(&serde_json::to_vec(&value).unwrap(), Phase::Ready).is_ok());
}
