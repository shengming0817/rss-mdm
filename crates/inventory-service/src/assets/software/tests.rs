use super::*;
use rss_mdm_inventory::{CollectionScope, Evidence, Platform, Scalar, Source};
use serde_json::json;

fn value(id: &str, name: &str, version: &str, publisher: &str, state: &str) -> Scalar {
    Scalar::Object(
        [
            ("id".into(), Scalar::String(id.into())),
            ("native_id".into(), Scalar::String(id.into())),
            ("name".into(), Scalar::String(name.into())),
            ("version".into(), Scalar::String(version.into())),
            ("publisher".into(), Scalar::String(publisher.into())),
            ("origin".into(), Scalar::String("win32.uninstall.64".into())),
            ("installation_state".into(), Scalar::String(state.into())),
        ]
        .into(),
    )
}
fn array() -> ArrayInput {
    ArrayInput {
        endpoint: "device-a".into(),
        source: SoftwareSource::Installations,
        platform: Platform::Windows,
        value: rss_mdm_inventory::ArrayValue {
            version: "a".repeat(64),
            count: 1,
            bytes: 64,
            digest: "b".repeat(64),
        },
        confirmed: true,
        evidence: Evidence {
            scope: CollectionScope::Device,
            source: Source::MdmWindows,
            dataset: Some("software".into()),
            registration: Some(Uuid::new_v4().to_string()),
            registration_generation: Some(1),
            epoch: Some(Uuid::new_v4().to_string()),
            snapshot_id: "snapshot".into(),
            observed_at: 1,
            received_at: 2,
            actor: None,
        },
    }
}
fn standard(id: Uuid) -> Record<Standard> {
    Record {
        id,
        revision: 1,
        definition: Some(Standard {
            name: "Example".into(),
            risk: Risk::Medium,
            tags: vec!["office".into()],
            assessments: Assessments::default(),
        }),
    }
}
fn mapping(id: Uuid, standard: Uuid, filter: &str) -> Record<Mapping> {
    Record {
        id,
        revision: 1,
        definition: Some(Mapping {
            standard,
            enabled: true,
            source: SoftwareSource::Installations,
            platform: Platform::Windows,
            origin: Some("win32.uninstall.64".into()),
            filter: filter.into(),
        }),
    }
}
#[test]
fn conjunction_cannot_combine_two_installations() {
    let predicate = filter::compile("name==Editor;version==2").unwrap();
    let old = evidence::item(
        SoftwareSource::Installations,
        Platform::Windows,
        &value("editor", "Editor", "1", "Acme", "installed"),
    )
    .unwrap();
    let other = evidence::item(
        SoftwareSource::Installations,
        Platform::Windows,
        &value("plugin", "Plugin", "2", "Acme", "installed"),
    )
    .unwrap();
    assert!(!filter::matches(&predicate, &old));
    assert!(!filter::matches(&predicate, &other));
    assert!(filter::matches(
        &predicate,
        &evidence::item(
            SoftwareSource::Installations,
            Platform::Windows,
            &value("editor", "Editor", "2", "Acme", "installed")
        )
        .unwrap()
    ));
    assert!(filter::compile("version=gt=1").is_err());
    assert!(filter::compile("unknown==x").is_err());
}
#[test]
fn mappings_require_identity_in_every_alternative() {
    for text in [
        "name==Editor",
        "nativeId==a,name==Editor",
        "name==Editor;version==2",
    ] {
        assert!(!filter::anchored(&filter::compile(text).unwrap()), "{text}");
    }
    for text in [
        "nativeId=in=(a,b)",
        "name==Editor;publisher==Acme",
        "(name==A;publisher==Acme),(name==B;publisher==Other)",
    ] {
        assert!(filter::anchored(&filter::compile(text).unwrap()), "{text}");
    }
}
#[test]
fn duplicate_rules_same_target_are_one_mapping_and_other_targets_conflict() {
    let id = Uuid::new_v4();
    let other = Uuid::new_v4();
    let input = array();
    let item = evidence::item(
        input.source,
        input.platform,
        &value("editor", "Editor", "1", "Acme", "installed"),
    )
    .unwrap();
    let mut configuration = Configuration {
        revision: 1,
        standards: vec![standard(id), standard(other)],
        mappings: vec![
            mapping(Uuid::new_v4(), id, "nativeId==editor"),
            mapping(Uuid::new_v4(), id, "name==Editor;publisher==Acme"),
        ],
    };
    let resolved = evidence::resolve(
        &configuration,
        &predicates(&configuration),
        &input,
        0,
        &item,
    )
    .unwrap();
    assert_eq!(resolved.standard, Some(id));
    assert_eq!(resolved.rules.len(), 2);
    configuration
        .mappings
        .push(mapping(Uuid::new_v4(), other, "nativeId==editor"));
    let resolved = evidence::resolve(
        &configuration,
        &predicates(&configuration),
        &input,
        0,
        &item,
    )
    .unwrap();
    assert_eq!(resolved.standard, None);
    assert!(matches!(resolved.identity,Identity::Conflict {candidates,..} if candidates.len()==2));
}
#[test]
fn unmapped_names_do_not_merge_publishers_or_anonymous_instances() {
    let configuration = Configuration {
        revision: 0,
        standards: vec![],
        mappings: vec![],
    };
    let input = array();
    let a = evidence::item(
        input.source,
        input.platform,
        &value("same", "Editor", "1", "Acme", "installed"),
    )
    .unwrap();
    let b = evidence::item(
        input.source,
        input.platform,
        &value("same", "Editor", "1", "Other", "installed"),
    )
    .unwrap();
    assert_ne!(
        evidence::resolve(&configuration, &predicates(&configuration), &input, 0, &a)
            .unwrap()
            .key,
        evidence::resolve(&configuration, &predicates(&configuration), &input, 0, &b)
            .unwrap()
            .key
    );
    let anonymous = evidence::item(
        SoftwareSource::AppleApplications,
        Platform::Macos,
        &Scalar::Object(Default::default()),
    )
    .unwrap();
    assert_ne!(
        evidence::resolve(
            &configuration,
            &predicates(&configuration),
            &input,
            0,
            &anonymous
        )
        .unwrap()
        .key,
        evidence::resolve(
            &configuration,
            &predicates(&configuration),
            &input,
            1,
            &anonymous
        )
        .unwrap()
        .key
    );
}
#[test]
fn registered_is_installed_but_provisioning_is_not() {
    for (state, expected) in [
        ("installed", true),
        ("registered", true),
        ("provisioned", false),
    ] {
        assert_eq!(
            evidence::item(
                SoftwareSource::Installations,
                Platform::Windows,
                &value("x", "X", "1", "Acme", state)
            )
            .unwrap()
            .installed,
            expected
        );
    }
}
#[test]
fn allowed_union_requires_negative_evidence_and_disabled_is_distinct() {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let policy = Assessment {
        threshold: None,
        allowed_groups: Some(vec![a, b]),
    };
    assert_eq!(
        filter::compliance(&Assessment::default(), &BTreeMap::new()),
        Compliance::Disabled
    );
    assert_eq!(
        filter::compliance(&policy, &[(a, Decision::NoMatch)].into()),
        Compliance::Unknown
    );
    assert_eq!(
        filter::compliance(
            &policy,
            &[(a, Decision::NoMatch), (b, Decision::Unknown)].into()
        ),
        Compliance::Unknown
    );
    assert_eq!(
        filter::compliance(
            &policy,
            &[(a, Decision::Match), (b, Decision::Unknown)].into()
        ),
        Compliance::Compliant
    );
    assert_eq!(
        filter::compliance(
            &policy,
            &[(a, Decision::NoMatch), (b, Decision::NoMatch)].into()
        ),
        Compliance::NonCompliant
    );
}
#[test]
fn standard_risk_is_explicit_and_has_only_three_levels() {
    for risk in ["low", "medium", "high"] {
        let standard: Standard =
            serde_json::from_value(json!({"name":"Editor","risk":risk})).unwrap();
        filter::validate_standard(&standard).unwrap();
    }
    for risk in [json!(null), json!("critical"), json!("unclassified")] {
        assert!(serde_json::from_value::<Standard>(json!({"name":"Editor","risk":risk})).is_err());
    }
    assert!(serde_json::from_value::<Standard>(json!({"name":"Editor"})).is_err());
}
#[test]
fn domain_policies_and_software_selection_are_independent() {
    let mut definition = standard(Uuid::new_v4()).definition.unwrap();
    definition.assessments.endpoint.threshold = Some(2);
    assert_eq!(
        definition
            .assessments
            .get(rss_mdm_group::AssetContext::AssociatedDevice)
            .threshold,
        None
    );
    definition.assessments.endpoint.allowed_groups = Some(vec![]);
    assert!(filter::validate_standard(&definition).is_err());
    let query: Query = serde_json::from_value(json!({})).unwrap();
    assert_eq!(query.context, rss_mdm_group::AssetContext::AssociatedDevice);
}

fn predicates(configuration: &Configuration) -> BTreeMap<Uuid, filter::Predicate> {
    configuration
        .mappings
        .iter()
        .filter_map(|r| {
            r.definition
                .as_ref()
                .map(|m| (r.id, filter::compile(&m.filter).unwrap()))
        })
        .collect()
}

#[test]
fn native_package_presence_and_provisioning_are_not_installation_proof() {
    for (users, expected, known) in [
        ("0", false, true),
        ("1", false, true),
        ("2", true, true),
        ("6", false, true),
        ("", false, false),
        ("unrecognized-user-list", false, false),
    ] {
        let value = Scalar::Object(
            [
                (
                    "registered_users_native".into(),
                    Scalar::String(users.into()),
                ),
                ("is_provisioned".into(), Scalar::Boolean(false)),
            ]
            .into(),
        );
        let item = evidence::item(SoftwareSource::WindowsStore, Platform::Windows, &value).unwrap();
        assert_eq!(item.installed, expected);
        assert_eq!(item.installation_known, known);
    }
}
