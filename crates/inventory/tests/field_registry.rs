//! Stable field identities are validated independently of the tenant's published catalog.
use rss_mdm_inventory::FieldKey;

#[test]
fn custom_field_identity_is_not_a_closed_product_enum() {
    let field = FieldKey::parse("custom.security_agent.healthy").unwrap();
    assert_eq!(field.as_str(), "custom.security_agent.healthy");
    let encoded = serde_json::to_string(&field).unwrap();
    assert_eq!(serde_json::from_str::<FieldKey>(&encoded).unwrap(), field);
}

#[test]
fn malformed_field_identities_are_rejected() {
    for value in [
        "",
        "custom",
        "custom..name",
        "custom.Name",
        "custom.name/other",
        "custom.name\0",
        "unowned.name",
    ] {
        assert!(FieldKey::parse(value).is_err(), "accepted {value:?}");
    }
    assert!(FieldKey::parse(&format!("custom.{}", "x".repeat(256))).is_err());
}

fn definition() -> rss_mdm_inventory::FieldDefinition {
    use rss_mdm_inventory::*;
    FieldDefinition {
        key: FieldKey::parse("custom.security_agent.healthy").unwrap(),
        version: 1,
        value_type: ValueType::Boolean,
        nullable: false,
        manual: false,
        sources: [(Source::AgentScript, 0), (Source::AgentOsquery, 0)].into(),
        platforms: [Platform::Windows, Platform::Macos].into(),
        sensitivity: Sensitivity::Standard,
        unit: None,
        searchable: true,
        item_key: None,
    }
}

#[test]
fn parsed_identity_does_not_bypass_registered_definition_or_type() {
    use rss_mdm_inventory::*;
    let catalog = Catalog::new(vec![definition()]).unwrap();
    assert!(
        catalog
            .definition(FieldKey::parse("custom.unregistered").unwrap())
            .is_err()
    );
    let definition = catalog.definition(definition().key).unwrap();
    assert!(definition.validate_scalar(&Scalar::Boolean(false)).is_ok());
    assert!(
        definition
            .validate_scalar(&Scalar::String("false".into()))
            .is_err()
    );
    assert!(Catalog::new(vec![definition.clone(), definition.clone()]).is_err());
    assert!(
        serde_json::from_value::<FieldDefinition>({
            let mut v = serde_json::to_value(definition).unwrap();
            v["expiresAt"] = serde_json::json!(1);
            v
        })
        .is_err()
    );
}

#[test]
fn frozen_collection_rejects_unregistered_source_wrong_coverage_and_duplicate_fields() {
    use rss_mdm_inventory::*;
    use rss_observation::{Batch, Body, Change, Id};
    let field = definition();
    let contract = CollectionDefinition::new(
        "security-health",
        1,
        Source::AgentScript,
        vec![field.clone()],
    )
    .unwrap();
    let batch = |body| {
        Batch::new(
            Id::new("batch").unwrap(),
            1,
            rss_contract::Timepoint::try_from(1).unwrap(),
            contract.coverage().unwrap(),
            body,
        )
        .unwrap()
    };
    let value = CollectedValue::Value(Scalar::Boolean(false))
        .encode(&field)
        .unwrap();
    assert!(
        contract
            .validate(&batch(Body::Snapshot(vec![Change::upsert(
                Id::new(field.key.as_str()).unwrap(),
                value.clone()
            )])))
            .is_ok()
    );
    assert!(
        CollectionDefinition::new(
            "security-health",
            1,
            Source::AgentBuiltin,
            vec![field.clone()]
        )
        .is_err()
    );
    assert!(
        contract
            .validate(&batch(Body::Snapshot(vec![Change::upsert(
                Id::new("custom.other").unwrap(),
                value
            )])))
            .is_err()
    );
    assert!(
        CollectionDefinition::new(
            "security-health",
            1,
            Source::AgentScript,
            vec![field.clone(), field]
        )
        .is_err()
    );
    let wrong =
        CollectionDefinition::new("different", 1, Source::AgentScript, vec![definition()]).unwrap();
    assert!(wrong.validate(&batch(Body::Snapshot(vec![]))).is_err());
    assert!(contract.validate(&batch(Body::Snapshot(vec![]))).is_ok());
}

#[test]
fn structured_inventory_has_bounded_shapes_and_stable_unique_items() {
    use rss_mdm_inventory::*;
    let catalog = Catalog::new(builtin::fields()).unwrap();
    let field = catalog
        .definition(FieldKey::parse("device.storage.devices").unwrap())
        .unwrap();
    let item = Scalar::Object(
        [
            ("id".into(), Scalar::String("disk-1".into())),
            ("name".into(), Scalar::String("main".into())),
            ("size_bytes".into(), Scalar::Integer(4096)),
        ]
        .into(),
    );
    assert!(field.validate_scalar(&Scalar::Array(vec![])).is_ok());
    assert!(
        field
            .validate_scalar(&Scalar::Array(vec![item.clone()]))
            .is_ok()
    );
    assert!(
        field
            .validate_scalar(&Scalar::Array(vec![item.clone(), item]))
            .is_err()
    );
    assert!(
        field
            .validate_scalar(&Scalar::Array(vec![Scalar::Object(Default::default())]))
            .is_err()
    );
    assert!(
        ValueType::Number
            .validate_value(&Scalar::Integer(1))
            .is_err()
    );
    assert!(
        Scalar::Number(ordered_float::NotNan::new(f64::INFINITY).unwrap())
            .validate()
            .is_err()
    );
}

#[test]
fn source_precedence_is_explicit_and_deletion_preserves_other_facts() {
    use rss_mdm_inventory::*;
    let fact = |source, value| SourceFact {
        state: State::Known(Scalar::Boolean(value)),
        last_known: None,
        evidence: Evidence {
            source,
            dataset: Some("collector".into()),
            registration: Some("reg".into()),
            registration_generation: Some(1),
            epoch: Some("epoch".into()),
            snapshot_id: "batch".into(),
            observed_at: 1,
            received_at: 2,
            actor: None,
        },
    };
    let mut field = definition();
    let script = fact(Source::AgentScript, true);
    let sql = fact(Source::AgentOsquery, false);
    assert_eq!(
        resolve(&field, vec![script.clone(), sql.clone()])
            .unwrap()
            .state,
        State::Conflict
    );
    field.sources.insert(Source::AgentOsquery, 1);
    assert_eq!(
        resolve(&field, vec![script.clone(), sql.clone()])
            .unwrap()
            .state,
        script.state
    );
    let removed = SourceFact {
        state: State::Deleted,
        last_known: Some(KnownValue {
            value: Scalar::Boolean(true),
            evidence: script.evidence.clone(),
        }),
        evidence: script.evidence,
    };
    let result = resolve(&field, vec![removed, sql.clone()]).unwrap();
    assert_eq!(result.state, sql.state);
    assert!(result.sources.iter().any(|s| s.last_known.is_some()));
}

#[test]
fn structured_paths_are_derived_from_registered_schemas_not_free_json_queries() {
    use rss_mdm_inventory::*;
    let catalog = Catalog::new(builtin::fields()).unwrap();
    let path = catalog
        .path(FieldKey::parse("device.storage.devices.size_bytes").unwrap())
        .unwrap();
    assert_eq!(path.value_type.kind(), Kind::Integer);
    assert!(path.many);
    assert!(
        catalog
            .path(FieldKey::parse("device.storage.devices.secret").unwrap())
            .is_err()
    );
    let item = |name: &str, size| {
        Scalar::Object(
            [
                ("id".into(), Scalar::String(name.into())),
                ("name".into(), Scalar::String(name.into())),
                ("size_bytes".into(), Scalar::Integer(size)),
            ]
            .into(),
        )
    };
    let value = Scalar::Array(vec![item("disk1", 100), item("disk2", 200)]);
    assert_eq!(
        path.values(&value).unwrap(),
        vec![&Scalar::Integer(100), &Scalar::Integer(200)]
    );
}
