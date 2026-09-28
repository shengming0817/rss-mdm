use super::*;
#[test]
fn profile_version_is_format_not_release_and_target_is_device_scoped() {
    let id = Uuid::new_v4();
    let d = super::super::protocol::decode(&firewall("com.rss.test", id, true).unwrap()).unwrap();
    assert_eq!(d["PayloadVersion"].as_signed_integer(), Some(1));
    assert_eq!(d["PayloadScope"].as_string(), Some("System"));
    let inner = d["PayloadContent"].as_array().unwrap()[0]
        .as_dictionary()
        .unwrap();
    assert_eq!(inner["EnableFirewall"].as_boolean(), Some(true));
    assert_ne!(identifier("tenant-a", "d"), identifier("tenant-b", "d"));
    assert_ne!(
        presence_digest("p", id, true),
        presence_digest("p", id, false)
    );
}
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
