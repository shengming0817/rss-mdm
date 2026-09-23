use rss_mdm_inventory::{Evidence, FieldKey, Scalar, SourceFact, State, resolve};
fn fact(value: &str, source: &str) -> SourceFact {
    SourceFact {
        state: State::Known(Scalar::String(value.into())),
        last_known: None,
        evidence: Evidence {
            source: rss_mdm_inventory::Source::parse(source).unwrap(),
            registration: Some("registration".into()),
            registration_generation: Some(1),
            epoch: Some("epoch".into()),
            snapshot_id: "batch".into(),
            observed_at: 1,
            received_at: 2,
            actor: None,
        },
    }
}
#[test]
fn typed_manual_values_cannot_overwrite_standard_fields() {
    assert!(
        FieldKey::OfficeFloor
            .validate_scalar(&Scalar::Integer(3))
            .is_ok()
    );
    assert!(
        FieldKey::OfficeFloor
            .validate_scalar(&Scalar::String("3".into()))
            .is_err()
    );
    assert!(!FieldKey::Model.definition().manual);
    assert!(FieldKey::AssetTag.definition().manual);
    assert_eq!(
        FieldKey::observed().collect::<Vec<_>>(),
        vec![FieldKey::Model, FieldKey::OsVersion]
    );
    assert_eq!(FieldKey::observed().count(), 2);
    assert_eq!(
        FieldKey::parse("unknown"),
        Err(rss_mdm_inventory::Invalid::UnknownField)
    );
    assert_eq!(
        FieldKey::OfficeFloor.validate_scalar(&Scalar::String("secret-value".into())),
        Err(rss_mdm_inventory::Invalid::TypeMismatch)
    );
    assert_eq!(
        Scalar::String("".into()).validate(),
        Err(rss_mdm_inventory::Invalid::Value)
    );
    assert!(Scalar::String("型".repeat(256)).validate().is_ok());
    assert_eq!(
        Scalar::String("型".repeat(257)).validate(),
        Err(rss_mdm_inventory::Invalid::Value)
    );
    assert_eq!(
        rss_mdm_inventory::Source::parse("unknown"),
        Err(rss_mdm_inventory::Invalid::UnknownSource)
    );
    assert_eq!(
        resolve(
            FieldKey::Model,
            vec![fact("x", "mdm.windows"), fact("x", "mdm.windows")]
        ),
        Err(rss_mdm_inventory::Invalid::DuplicateSource)
    );
    let encoded = rss_mdm_inventory::CollectedValue::Unsupported
        .encode(FieldKey::Model)
        .unwrap();
    assert_eq!(
        rss_mdm_inventory::CollectedValue::decode(FieldKey::Model, &encoded).unwrap(),
        rss_mdm_inventory::CollectedValue::Unsupported
    );
    assert!(rss_mdm_inventory::CollectedValue::decode(FieldKey::Model, b"legacy").is_err());
    assert!(
        rss_mdm_inventory::CollectedValue::Known("".into())
            .encode(FieldKey::Model)
            .is_err()
    );
    for source in [
        rss_mdm_inventory::ReportSource::MdmWindows,
        rss_mdm_inventory::ReportSource::MdmApple,
        rss_mdm_inventory::ReportSource::AgentBuiltin,
    ] {
        assert_eq!(
            rss_mdm_inventory::ReportSource::parse(source.as_str()).unwrap(),
            source
        );
        assert!(
            FieldKey::Model
                .definition()
                .sources
                .contains(&source.into())
        );
    }
    assert!(
        rss_mdm_inventory::CollectedValue::decode(
            FieldKey::Model,
            br#"{"kind":"unsupported","validUntil":5}"#
        )
        .is_err()
    );
    assert!(rss_mdm_inventory::ReportSource::parse("manual").is_err());
    assert!(rss_mdm_inventory::Source::parse("other").is_err());
    let mut manual = fact("tag", "manual");
    manual.evidence.registration = None;
    manual.evidence.registration_generation = None;
    manual.evidence.epoch = None;
    manual.evidence.actor = Some("alice".into());
    for state in [State::Missing, State::Unsupported, State::Conflict] {
        manual.state = state;
        assert!(resolve(FieldKey::AssetTag, vec![manual.clone()]).is_err());
    }
    manual.state = State::Deleted;
    manual.last_known = Some(rss_mdm_inventory::KnownValue {
        value: Scalar::String("tag".into()),
        evidence: manual.evidence.clone(),
    });
    manual.last_known.as_mut().unwrap().evidence.actor = Some("bob".into());
    assert!(resolve(FieldKey::AssetTag, vec![manual.clone()]).is_ok());
    manual.last_known.as_mut().unwrap().evidence.source = rss_mdm_inventory::Source::MdmWindows;
    assert!(resolve(FieldKey::AssetTag, vec![manual]).is_err());
}
#[test]
fn source_conflict_preserves_both_values_and_equal_sources_resolve() {
    let a = fact("A", "mdm.windows");
    let b = fact("B", "agent.builtin");
    let result = resolve(FieldKey::Model, vec![a.clone(), b]).unwrap();
    assert_eq!(result.state, State::Conflict);
    assert_eq!(result.sources.len(), 2);
    assert_eq!(
        resolve(FieldKey::Model, vec![a, fact("A", "agent.builtin")])
            .unwrap()
            .state,
        State::Known(Scalar::String("A".into()))
    );
}
#[test]
fn deletion_does_not_remove_another_source_value() {
    let mut removed = fact("old", "mdm.windows");
    removed.last_known = Some(rss_mdm_inventory::KnownValue {
        value: Scalar::String("old".into()),
        evidence: removed.evidence.clone(),
    });
    removed.state = State::Deleted;
    let result = resolve(FieldKey::Model, vec![removed, fact("new", "agent.builtin")]).unwrap();
    assert_eq!(result.state, State::Known(Scalar::String("new".into())));
    assert_eq!(
        result.sources[1]
            .last_known
            .as_ref()
            .map(|k| k.value.clone()),
        Some(Scalar::String("old".into()))
    );
}

#[test]
fn apple_observations_use_the_canonical_asset_resolver() {
    for field in FieldKey::observed() {
        let observed = fact("Apple value", "mdm.apple");
        assert_eq!(
            resolve(field, vec![observed.clone()]).unwrap().state,
            observed.state
        );
        assert_eq!(
            resolve(field, vec![observed, fact("Other value", "agent.builtin")])
                .unwrap()
                .state,
            State::Conflict
        );
    }
    assert_eq!(
        resolve(FieldKey::AssetTag, vec![fact("Apple value", "mdm.apple")]),
        Err(rss_mdm_inventory::Invalid::SourceNotAllowed)
    );
}
