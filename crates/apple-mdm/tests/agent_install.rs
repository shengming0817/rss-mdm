use crate::{agent_install as agent, protocol as wire};
use plist::Value;
use uuid::Uuid;
#[test]
fn fixed_manifest_contains_hash_and_public_operation_only() {
    let op = Uuid::new_v4();
    let d = agent::install(
        "com.rss.agent",
        "1.2.3",
        "https://mdm.example/package",
        [7; 32],
        op,
    )
    .unwrap();
    assert_eq!(
        wire::text(&d, "RequestType").unwrap(),
        "InstallEnterpriseApplication"
    );
    assert_eq!(
        d["Configuration"].as_dictionary().unwrap()["RSSInstallationOperation"].as_string(),
        Some(op.to_string().as_str())
    );
    let xml = String::from_utf8(wire::xml(d).unwrap()).unwrap();
    assert!(xml.contains(&"07".repeat(32)));
    assert!(!xml.contains("RemoveAppWhenMDMProfileIsRemoved"));
    assert!(
        agent::install(
            "com.rss.agent",
            "1.2.3",
            "http://mdm.example/package",
            [7; 32],
            op
        )
        .is_err()
    );
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
