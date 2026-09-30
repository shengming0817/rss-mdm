use rss_mdm_inventory::{AgentInstallation, FieldKey, MdmEnrollment, Scalar, Source};
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
    let agent = FieldKey::AgentInstallation;
    assert_eq!(
        agent.definition().sources,
        &[Source::MdmWindows, Source::MdmApple]
    );
    assert_eq!(
        FieldKey::MdmEnrollment.definition().sources,
        &[Source::AgentBuiltin]
    );
    assert!(
        agent
            .validate_scalar(&Scalar::String("absent".into()))
            .is_ok()
    );
    assert!(
        agent
            .validate_scalar(&Scalar::String("offline".into()))
            .is_err()
    );
    assert!(
        FieldKey::MdmEnrollment
            .validate_scalar(&Scalar::String("other_organization".into()))
            .is_ok()
    );
    assert!(
        FieldKey::MdmEnrollment
            .validate_scalar(&Scalar::String("absent".into()))
            .is_err()
    );
}
