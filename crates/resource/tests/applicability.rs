use rss_mdm_resource::{Applicability, CollectionEnvironment, TemplateScope};
#[test]
fn unknown_or_older_evidence_never_satisfies_declared_requirements() {
    let requirements = Applicability {
        minimum_os_version: Some("10.0.26100".into()),
        minimum_build: Some(26100),
        editions: ["48".into()].into(),
        enrollments: ["primary".into()].into(),
        tools: [("osquery".into(), "5.23.1".into())].into(),
        capabilities: ["osquery".into()].into(),
    };
    let mut facts = CollectionEnvironment {
        os_version: Some("10.0.26100.1".into()),
        build: Some(26100),
        edition: Some("48".into()),
        tools: [("osquery".into(), "5.23.1".into())].into(),
    };
    let capabilities = ["osquery".into()].into();
    assert!(requirements.allows(&facts, "primary", &capabilities));
    assert!(!requirements.allows(&facts, "user", &capabilities));
    assert!(!requirements.allows(&facts, "primary", &Default::default()));
    facts.tools.insert("osquery".into(), "5.9.0".into());
    assert!(!requirements.allows(&facts, "primary", &capabilities));
    assert!(!requirements.allows(&CollectionEnvironment::default(), "primary", &capabilities));
}
#[test]
fn unsupported_ranges_are_not_coerced_to_device_scope() {
    for scope in [
        TemplateScope::User {
            identity: "501".into(),
        },
        TemplateScope::Volume {
            identity: "volume-uuid".into(),
        },
        TemplateScope::Prefix {
            path: "/Applications".into(),
        },
        TemplateScope::Source {
            identity: "brew".into(),
        },
    ] {
        assert!(scope.validate_executable().is_err());
    }
}
