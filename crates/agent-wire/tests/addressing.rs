use rss_mdm_agent_wire::runtime::*;
use uuid::Uuid;

#[test]
fn exact_addresses_normalize_aliases_without_guessing_names() {
    let id = Uuid::new_v4();
    assert_eq!(
        PolicyAlias::parse("  Repair.APP_1-2 ").unwrap().as_str(),
        "repair.app_1-2"
    );
    for invalid in ["", "  ", "a/b", "a b", "修复", "a\0b"] {
        assert!(PolicyAlias::parse(invalid).is_err());
    }
    assert!(PolicyAlias::parse(&"a".repeat(65)).is_err());
    assert_eq!(
        CapabilitySelector::ToolName {
            name: policy_tool_name(id)
        }
        .policy_id()
        .unwrap(),
        Some(id)
    );
    assert!(
        CapabilitySelector::ToolName {
            name: id.to_string()
        }
        .policy_id()
        .is_err()
    );
    assert!(
        CapabilitySelector::Id { id: Uuid::nil() }
            .policy_id()
            .is_err()
    );
    assert!(
        CapabilitySelector::Alias {
            alias: PolicyAlias::parse(&policy_tool_name(id)).unwrap()
        }
        .policy_id()
        .unwrap()
        .is_none()
    );
}

#[test]
fn software_node_identity_tracks_definition_not_position() {
    let definition = SoftwareStepDefinition {
        resource: "application".into(),
        version: "1".into(),
        variant: "macos".into(),
        digest: [1; 32],
    };
    let original = definition.step_id().unwrap();
    assert_eq!(definition.clone().step_id().unwrap(), original);
    let mut other = definition.clone();
    other.version = "2".into();
    assert_ne!(other.step_id().unwrap(), original);
    other = definition.clone();
    other.resource = "same-package-other-resource".into();
    assert_ne!(other.step_id().unwrap(), original);
    other = definition;
    other.digest = [2; 32];
    assert_ne!(other.step_id().unwrap(), original);
}
