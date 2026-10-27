use crate::{protocol as wire, software as agent};
use plist::Value;
#[test]
fn retained_bundle_versions_are_presence_without_a_unique_current_version() {
    let report = wire::dictionary([(
        "InstalledApplicationList",
        Value::Array(
            ["0.1.13", "0.1.19", "0.1.19"]
                .into_iter()
                .map(|version| {
                    wire::dictionary([
                        ("Identifier", "com.rss.agent".into()),
                        ("Version", version.into()),
                        ("Installing", false.into()),
                    ])
                    .into()
                })
                .collect(),
        ),
    )]);
    assert_eq!(
        agent::presence(&report, "com.rss.agent").unwrap(),
        agent::Presence::PresentUnverified { version: None }
    );
    assert_eq!(
        agent::presence(&report, "com.rss.other").unwrap(),
        agent::Presence::Absent
    );
}
#[test]
fn bundle_selection_checks_all_copies_without_hiding_partial_or_installing_reports() {
    let item = |identity: &str, installing: bool| {
        Value::Dictionary(wire::dictionary([
            ("Identifier", identity.into()),
            ("Version", "1.2.3".into()),
            ("Installing", installing.into()),
        ]))
    };
    let report = |items| wire::dictionary([("InstalledApplicationList", Value::Array(items))]);
    let copies = vec![
        item("com.rss.other", false),
        item("com.rss.agent", false),
        item("com.rss.agent", false),
    ];
    assert_eq!(
        agent::presence(&report(copies.clone()), "com.rss.agent").unwrap(),
        agent::Presence::PresentUnverified {
            version: Some("1.2.3".into())
        }
    );
    let mut installing = copies.clone();
    installing.push(item("com.rss.agent", true));
    assert_eq!(
        agent::presence(&report(installing), "com.rss.agent").unwrap(),
        agent::Presence::Installing
    );
    let mut partial = copies;
    partial.push(wire::dictionary([("Identifier", "com.rss.agent".into())]).into());
    assert!(agent::presence(&report(partial), "com.rss.agent").is_err());
}
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
            version: Some("1.2.3".into())
        }
    );
}

#[test]
fn enterprise_package_metadata_does_not_prove_an_installed_application() {
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
    // Enterprise package identifiers name receipts, not necessarily application bundles.
    // Both remote and inline manifests must leave package effect unverified.
    assert!(agent::observation(&input).unwrap().is_none());
}
