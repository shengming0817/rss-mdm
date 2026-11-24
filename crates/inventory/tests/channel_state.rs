use rss_mdm_inventory::{AgentInstallation, MdmEnrollment, Scalar, Source, builtin};
fn definition(field: rss_mdm_inventory::FieldKey) -> rss_mdm_inventory::FieldDefinition {
    rss_mdm_inventory::Catalog::new(builtin::fields())
        .unwrap()
        .definition(field)
        .unwrap()
        .clone()
}
#[test]
fn only_explicit_absence_triggers_onboarding() {
    assert!(AgentInstallation::Absent.requires_install());
    assert!(!AgentInstallation::Installed.requires_install());
    assert!(!AgentInstallation::Unknown.requires_install());
    assert!(MdmEnrollment::Unenrolled.requires_enrollment());
    for state in [
        MdmEnrollment::ThisOrganization,
        MdmEnrollment::OtherOrganization,
        MdmEnrollment::Unknown,
    ] {
        assert!(!state.requires_enrollment());
    }
}
#[test]
fn channel_facts_have_a_fixed_value_and_source_contract() {
    let agent = builtin::AGENT_INSTALLATION;
    assert_eq!(
        definition(agent)
            .sources
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        &[Source::MdmApple, Source::MdmWindows]
    );
    assert_eq!(
        definition(builtin::MDM_ENROLLMENT)
            .sources
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        &[Source::AgentBuiltin]
    );
    assert!(
        definition(agent)
            .validate_scalar(&Scalar::String("absent".into()))
            .is_ok()
    );
    assert!(
        definition(agent)
            .validate_scalar(&Scalar::String("offline".into()))
            .is_err()
    );
    assert!(
        definition(builtin::MDM_ENROLLMENT)
            .validate_scalar(&Scalar::String("other_organization".into()))
            .is_ok()
    );
    assert!(
        definition(builtin::MDM_ENROLLMENT)
            .validate_scalar(&Scalar::String("absent".into()))
            .is_err()
    );
}

#[test]
fn module_collection_matches_the_da_report() {
    use rss_mdm_inventory::ValueType;
    use std::collections::BTreeSet;
    let schema =
        serde_json::to_value(schemars::schema_for!(rss_mdm_agent_wire::da::ClientModules)).unwrap();
    let ValueType::Object { properties } = definition(builtin::CLIENT_MODULES).value_type else {
        panic!("expected module object")
    };
    let names = |values: &serde_json::Value| -> BTreeSet<String> {
        values.as_object().unwrap().keys().cloned().collect()
    };
    let required = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(names(&schema["properties"]), required);
    assert_eq!(
        properties.keys().cloned().collect::<BTreeSet<_>>(),
        required
    );
    for (key, ty) in properties {
        let pointer = schema["properties"][&key]["$ref"]
            .as_str()
            .unwrap()
            .strip_prefix('#')
            .unwrap();
        let field = schema.pointer(pointer).unwrap();
        match ty {
            ValueType::Record { properties } => {
                assert_eq!(
                    properties.keys().cloned().collect::<BTreeSet<_>>(),
                    names(&field["properties"])
                );
                for (name, property) in properties {
                    assert_eq!(
                        property.required,
                        field["required"]
                            .as_array()
                            .is_some_and(|names| names.iter().any(|k| k == &name))
                    );
                    assert_eq!(property.value_type, ValueType::Boolean);
                    assert!(
                        field["properties"][name]["type"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|v| v == "boolean")
                    );
                }
            }
            ValueType::Enum { values } => {
                let states: BTreeSet<String> = field["oneOf"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s["const"].as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(values, states);
            }
            _ => panic!("unexpected module property {key}"),
        }
    }
}
