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
