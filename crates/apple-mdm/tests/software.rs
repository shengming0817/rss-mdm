use crate::{protocol as wire, software as agent};
use plist::Value;
#[test]
fn complete_empty_query_is_absence_but_partial_and_installing_are_unknown() {
    assert_eq!(
        agent::presence(
            &wire::dictionary([("InstalledApplicationList", Value::Array(vec![]))]),
            "com.rss.agent"
        )
        .unwrap(),
        agent::Presence::Absent
    );
    assert!(agent::presence(&plist::Dictionary::new(), "com.rss.agent").is_err());
    let item = wire::dictionary([
        ("Identifier", "com.rss.agent".into()),
        ("Version", "1.2.3".into()),
        ("Installing", true.into()),
    ]);
    assert_eq!(
        agent::presence(
            &wire::dictionary([("InstalledApplicationList", Value::Array(vec![item.into()]))]),
            "com.rss.agent"
        )
        .unwrap(),
        agent::Presence::Installing
    );
    assert!(
        agent::presence(
            &wire::dictionary([(
                "InstalledApplicationList",
                Value::Array(vec![plist::Dictionary::new().into()])
            )]),
            "com.rss.agent"
        )
        .is_err()
    );
}

#[test]
fn bundle_version_and_untrusted_team_field_do_not_verify_installation() {
    let item = wire::dictionary([
        ("Identifier", "com.rss.agent".into()),
        ("Version", "1.2.3".into()),
        ("TeamID", "RSS1234567".into()),
    ]);
    assert_eq!(
        agent::presence(
            &wire::dictionary([("InstalledApplicationList", Value::Array(vec![item.into()]))]),
            "com.rss.agent"
        )
        .unwrap(),
        agent::Presence::PresentUnverified {
            version: "1.2.3".into()
        }
    );
}

#[test]
fn software_observation_uses_native_identities_and_never_guesses_from_a_url() {
    use crate::native::input::{CommandInput, Fields};
    let command = |fields| CommandInput {
        request_type: "InstallEnterpriseApplication".into(),
        fields: Fields::from_plist(&fields).unwrap(),
    };
    let remote = command(wire::dictionary([(
        "ManifestURL",
        "https://packages.example.test/manifest".into(),
    )]));
    assert!(agent::observation(&remote).unwrap().is_none());
    let items = ["org.example.two", "org.example.one"]
        .into_iter()
        .map(|id| {
            Value::Dictionary(wire::dictionary([(
                "metadata",
                Value::Dictionary(wire::dictionary([("bundle-identifier", id.into())])),
            )]))
        })
        .collect();
    let input = command(wire::dictionary([(
        "Manifest",
        Value::Dictionary(wire::dictionary([("items", Value::Array(items))])),
    )]));
    let followup = agent::observation(&input).unwrap().unwrap();
    assert_eq!(followup.request_type, "InstalledApplicationList");
    assert_eq!(
        followup.fields.to_plist().unwrap()["Identifiers"],
        Value::Array(vec!["org.example.one".into(), "org.example.two".into()])
    );
}
