use rss_mdm_inventory::builtin;
use rss_mdm_inventory::{Evidence, FieldKey, Scalar, SourceFact, State};
fn definition(field: FieldKey) -> rss_mdm_inventory::FieldDefinition {
    rss_mdm_inventory::Catalog::new(builtin::fields())
        .unwrap()
        .definition(field)
        .unwrap()
        .clone()
}
fn resolve(
    field: FieldKey,
    sources: Vec<SourceFact>,
) -> rss_mdm_inventory::Result<rss_mdm_inventory::ResolvedField> {
    rss_mdm_inventory::resolve(&definition(field), sources)
}
fn fact(value: &str, source: &str) -> SourceFact {
    SourceFact {
        state: State::Known(Scalar::String(value.into())),
        last_known: None,
        evidence: Evidence {
            source: rss_mdm_inventory::Source::parse(source).unwrap(),
            dataset: Some("collector".into()),
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
        definition(builtin::OFFICE_FLOOR)
            .validate_scalar(&Scalar::Integer(3))
            .is_ok()
    );
    assert!(
        definition(builtin::OFFICE_FLOOR)
            .validate_scalar(&Scalar::String("3".into()))
            .is_err()
    );
    assert!(!definition(builtin::MODEL).manual);
    assert!(definition(builtin::ASSET_TAG).manual);
    assert_eq!(
        FieldKey::parse("unknown"),
        Err(rss_mdm_inventory::Invalid::UnknownField)
    );
    assert_eq!(
        definition(builtin::OFFICE_FLOOR).validate_scalar(&Scalar::String("secret-value".into())),
        Err(rss_mdm_inventory::Invalid::TypeMismatch)
    );
    assert_eq!(
        definition(builtin::ASSET_TAG).validate_scalar(&Scalar::String("".into())),
        Err(rss_mdm_inventory::Invalid::TypeMismatch)
    );
    assert!(
        definition(builtin::ASSET_TAG)
            .validate_scalar(&Scalar::String("型".repeat(256)))
            .is_ok()
    );
    assert_eq!(
        definition(builtin::ASSET_TAG).validate_scalar(&Scalar::String("型".repeat(257))),
        Err(rss_mdm_inventory::Invalid::TypeMismatch)
    );
    assert_eq!(
        rss_mdm_inventory::Source::parse("unknown"),
        Err(rss_mdm_inventory::Invalid::UnknownSource)
    );
    assert_eq!(
        resolve(
            builtin::MODEL,
            vec![fact("x", "mdm.windows"), fact("x", "mdm.windows")]
        ),
        Err(rss_mdm_inventory::Invalid::DuplicateSource)
    );
    let encoded = rss_mdm_inventory::CollectedValue::Unsupported
        .encode(&definition(builtin::MODEL))
        .unwrap();
    assert_eq!(
        rss_mdm_inventory::CollectedValue::decode(&definition(builtin::MODEL), &encoded).unwrap(),
        rss_mdm_inventory::CollectedValue::Unsupported
    );
    assert!(
        rss_mdm_inventory::CollectedValue::decode(&definition(builtin::MODEL), b"legacy").is_err()
    );
    assert!(
        rss_mdm_inventory::CollectedValue::Value(Scalar::String("".into()))
            .encode(&definition(builtin::MODEL))
            .is_err()
    );
    for source in [
        rss_mdm_inventory::ReportSource::MdmWindows,
        rss_mdm_inventory::ReportSource::MdmApple,
        rss_mdm_inventory::ReportSource::AgentBuiltin,
    ] {
        assert_eq!(
            rss_mdm_inventory::Source::from(source).channel(),
            Some(source.channel())
        );
        assert_eq!(
            rss_mdm_inventory::ReportSource::parse(source.as_str()).unwrap(),
            source
        );
        assert!(
            definition(builtin::MODEL)
                .sources
                .contains_key(&source.into())
        );
    }
    assert!(
        rss_mdm_inventory::CollectedValue::decode(
            &definition(builtin::MODEL),
            br#"{"kind":"unsupported","validUntil":5}"#
        )
        .is_err()
    );
    assert!(rss_mdm_inventory::ReportSource::parse("manual").is_err());
    assert!(rss_mdm_inventory::Source::parse("other").is_err());
    let mut manual = fact("tag", "manual");
    manual.evidence.dataset = None;
    manual.evidence.registration = None;
    manual.evidence.registration_generation = None;
    manual.evidence.epoch = None;
    manual.evidence.actor = Some("alice".into());
    for state in [State::Missing, State::Unsupported, State::Conflict] {
        manual.state = state;
        assert!(resolve(builtin::ASSET_TAG, vec![manual.clone()]).is_err());
    }
    manual.state = State::Deleted;
    manual.last_known = Some(rss_mdm_inventory::KnownValue {
        value: Scalar::String("tag".into()),
        evidence: manual.evidence.clone(),
    });
    manual.last_known.as_mut().unwrap().evidence.actor = Some("bob".into());
    assert!(resolve(builtin::ASSET_TAG, vec![manual.clone()]).is_ok());
    manual.last_known.as_mut().unwrap().evidence.source = rss_mdm_inventory::Source::MdmWindows;
    assert!(resolve(builtin::ASSET_TAG, vec![manual]).is_err());
}
#[test]
fn source_conflict_preserves_both_values_and_equal_sources_resolve() {
    let a = fact("A", "mdm.windows");
    let b = fact("B", "agent.builtin");
    let result = resolve(builtin::MODEL, vec![a.clone(), b]).unwrap();
    assert_eq!(result.state, State::Conflict);
    assert_eq!(result.sources.len(), 2);
    assert_eq!(
        resolve(builtin::MODEL, vec![a, fact("A", "agent.builtin")])
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
    let result = resolve(builtin::MODEL, vec![removed, fact("new", "agent.builtin")]).unwrap();
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
    for field in [builtin::MODEL, builtin::OS_VERSION] {
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
        resolve(builtin::ASSET_TAG, vec![fact("Apple value", "mdm.apple")]),
        Err(rss_mdm_inventory::Invalid::SourceNotAllowed)
    );
}

#[test]
fn keyed_list_consensus_ignores_provider_row_order() {
    use rss_mdm_inventory::{ValueType, resolve};
    let mut field = definition(builtin::MODEL);
    field.item_key = Some("id".into());
    field.value_type = ValueType::Array {
        max_items: 10,
        items: Box::new(ValueType::Object {
            properties: [(
                "id".into(),
                ValueType::String {
                    max_length: 20,
                    allow_empty: false,
                },
            )]
            .into(),
        }),
    };
    let item = |id: &str| Scalar::Object([("id".into(), Scalar::String(id.into()))].into());
    let mut a = fact("unused", "mdm.windows");
    a.state = State::Known(Scalar::Array(vec![item("a"), item("b")]));
    let mut b = fact("unused", "agent.builtin");
    b.state = State::Known(Scalar::Array(vec![item("b"), item("a")]));
    assert_eq!(
        resolve(&field, vec![a, b]).unwrap().state,
        State::Known(Scalar::Array(vec![item("a"), item("b")]))
    );
}
