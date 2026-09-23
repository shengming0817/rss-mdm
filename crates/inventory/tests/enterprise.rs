use rss_mdm_inventory::{FieldKey, Scalar, Source};
#[test]
fn enterprise_fields_are_typed_collected_and_not_manual_assignments() {
    let version = FieldKey::parse("custom.corporate_agent.version").unwrap();
    let health = FieldKey::parse("custom.corporate_agent.healthy").unwrap();
    assert!(!version.is_manual());
    assert!(!health.is_manual());
    assert!(health.validate_scalar(&Scalar::Boolean(true)).is_ok());
    assert!(
        health
            .validate_scalar(&Scalar::String("true".into()))
            .is_err()
    );
    assert_eq!(version.definition().sources, &[Source::AgentScript]);
    assert!(!FieldKey::OBSERVED.contains(&version));
}

#[test]
fn enterprise_scopes_cannot_forge_builtin_source_or_other_field_coverage() {
    use rss_mdm_inventory::{CollectedValue, enterprise_coverage, scope_coverage, validate};
    use rss_observation::{Batch, Body, Change, Epoch, Id, Registration, Scope};
    let field = FieldKey::CorporateAgentHealthy;
    let scope = |source: &str, dataset: &str| {
        Scope::new(
            rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            Id::new("object").unwrap(),
            Registration::new("registration").unwrap(),
            Id::new(source).unwrap(),
            Id::new(dataset).unwrap(),
            Epoch::new("epoch").unwrap(),
        )
    };
    assert!(scope_coverage(&scope("agent.builtin", field.as_str())).is_err());
    assert!(scope_coverage(&scope("agent.script", "inventory")).is_err());
    assert!(scope_coverage(&scope("agent.script", field.as_str())).is_ok());
    let payload = CollectedValue::Scalar(Scalar::Boolean(false))
        .encode(field)
        .unwrap();
    let batch = |coverage| {
        Batch::new(
            Id::new("batch").unwrap(),
            0,
            rss_contract::Timepoint::try_from(1).unwrap(),
            coverage,
            Body::Snapshot(vec![Change::upsert(
                Id::new(field.as_str()).unwrap(),
                payload.clone(),
            )]),
        )
        .unwrap()
    };
    assert!(validate(&batch(enterprise_coverage(field))).is_ok());
    assert!(validate(&batch(enterprise_coverage(FieldKey::CorporateAgentVersion))).is_err());
    assert!(validate(&batch(rss_mdm_inventory::coverage())).is_err());
    assert!(CollectedValue::Known("true".into()).encode(field).is_err());
}
