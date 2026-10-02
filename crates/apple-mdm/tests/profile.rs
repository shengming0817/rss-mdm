use super::*;
#[test]
fn missing_list_wrong_version_and_duplicates_never_prove_absence() {
    let id = Uuid::new_v4();
    assert!(presence(&Dictionary::new(), "p", id).is_err());
    let profile = dictionary([
        ("PayloadIdentifier", "p".into()),
        ("PayloadUUID", Uuid::new_v4().to_string().into()),
    ]);
    let d = dictionary([("ProfileList", Value::Array(vec![profile.clone().into()]))]);
    assert!(matches!(presence(&d, "p", id), Err(Error::Conflict)));
    let d = dictionary([(
        "ProfileList",
        Value::Array(vec![profile.clone().into(), profile.into()]),
    )]);
    assert!(presence(&d, "p", id).is_err());
    assert!(
        !presence(
            &dictionary([("ProfileList", Value::Array(vec![]))]),
            "p",
            id
        )
        .unwrap()
    );
}
