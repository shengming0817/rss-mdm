use rss_mdm_inventory::{
    Catalog, CollectedValue, CollectionDefinition, CollectionProgress, CollectionScope, FieldKey,
    NativeValue, Property, Quality, Scalar, Source, UnknownReason, ValueType, builtin,
};
use serde_json::json;

#[test]
fn user_scope_survives_roundtrip_and_is_not_an_agent_scope() {
    let scope = CollectionScope::User {
        identity: "4f2ea789-557a-48b1-b571-c6a0915d0e23".into(),
    };
    let field = builtin::fields()
        .into_iter()
        .find(|f| f.key == builtin::MODEL)
        .unwrap();
    let d = CollectionDefinition::new(
        scope.clone(),
        "apple.user",
        1,
        Source::MdmApple,
        vec![field.clone()],
    )
    .unwrap();
    let decoded: CollectionDefinition =
        serde_json::from_slice(&serde_json::to_vec(&d).unwrap()).unwrap();
    assert_eq!(decoded.collection_scope(), &scope);
    assert_eq!(d.fingerprint().unwrap(), decoded.fingerprint().unwrap());
    assert!(
        CollectionDefinition::new(scope, "agent", 1, Source::AgentBuiltin, vec![field]).is_err()
    );
}

#[test]
fn record_optional_metadata_remains_absent_and_item_identity_is_required() {
    let mut f = builtin::fields()
        .into_iter()
        .find(|f| f.key == builtin::MODEL)
        .unwrap();
    f.value_type = ValueType::Array {
        max_items: 10,
        items: Box::new(ValueType::Record {
            properties: [
                (
                    "id".into(),
                    Property {
                        value_type: ValueType::String {
                            max_length: 100,
                            allow_empty: false,
                        },
                        required: true,
                    },
                ),
                (
                    "enabled".into(),
                    Property {
                        value_type: ValueType::Boolean,
                        required: false,
                    },
                ),
            ]
            .into(),
        }),
    };
    f.item_key = Some("id".into());
    f.validate().unwrap();
    let v = f.value_type.decode_json(&json!([{"id":"a"}])).unwrap();
    f.validate_scalar(&v).unwrap();
    let catalog = Catalog::new(vec![f.clone()]).unwrap();
    assert!(
        catalog
            .path(FieldKey::parse("device.model.enabled").unwrap())
            .unwrap()
            .values(&v)
            .unwrap()
            .is_empty()
    );
    for bad in [
        json!([{"enabled":true}]),
        json!([{"id":"a","enabled":null}]),
        json!([{"id":"a","secret":"x"}]),
    ] {
        assert!(f.value_type.decode_json(&bad).is_err());
    }
    assert!(
        f.canonical_value(Scalar::Array(vec![
            match &v {
                Scalar::Array(a) => a[0].clone(),
                _ => unreachable!(),
            };
            2
        ]))
        .is_err()
    );
}

#[test]
fn explicit_unknown_is_delivered_as_partial_not_a_failed_attempt_or_tombstone() {
    let f = builtin::fields()
        .into_iter()
        .find(|f| f.key == builtin::MODEL)
        .unwrap();
    let d = CollectionDefinition::new(
        CollectionScope::Device,
        "ddm",
        1,
        Source::MdmApple,
        vec![f.clone()],
    )
    .unwrap();
    let unknown = CollectedValue::Unknown {
        reason: UnknownReason::UnorderedConflict,
    };
    let p = CollectionProgress::native_partial(
        d,
        [(f.key, NativeValue::Value(unknown.clone()))].into(),
        1,
    )
    .unwrap();
    assert_eq!(p.fields()[&f.key].quality, Quality::Unknown);
    let b = p.body().unwrap().unwrap();
    assert!(matches!(b, rss_observation::Body::Partial(_)));
    assert_eq!(
        CollectedValue::decode(&f, b.changes()[0].value().unwrap()).unwrap(),
        unknown
    );
    let restored: CollectionProgress =
        serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
    assert_eq!(restored, p);
}

#[test]
fn declarative_certificate_projection_has_a_fixed_secret_boundary() {
    let (_, field) = rss_mdm_inventory::builtin::apple_status::fields()
        .into_iter()
        .find(|(name, _)| *name == "security.certificate.list")
        .unwrap();
    let value = serde_json::json!([{"identifier":"one","is-identity":true,"subject-summary":"example","data":"secret-der","future-secret":"hidden"}]);
    let safe = rss_mdm_inventory::builtin::apple_status::sanitized(&field.value_type, &value);
    assert_eq!(
        safe,
        serde_json::json!([{"identifier":"one","is_identity":true,"subject_summary":"example"}])
    );
    assert!(field.value_type.decode_json(&safe).is_ok());
}

#[test]
fn declarative_capabilities_preserve_omitted_declaration_categories() {
    let (_, field) = builtin::apple_status::fields()
        .into_iter()
        .find(|(name, _)| *name == "management.client-capabilities")
        .unwrap();
    let reported = json!({
        "supported-features": {},
        "supported-versions": ["1.0"],
        "supported-payloads": {
            "declarations": {"configurations": ["com.apple.configuration.management.status-subscriptions"]},
            "status-items": ["device.operating-system.version"]
        }
    });
    let safe = builtin::apple_status::sanitized(&field.value_type, &reported);
    let value = field
        .canonical_value(field.value_type.decode_json(&safe).unwrap())
        .unwrap();
    let catalog = Catalog::new(vec![field.clone()]).unwrap();
    let omitted = FieldKey::parse(&format!(
        "{}.supported_payloads.declarations.activations",
        field.key.as_str()
    ))
    .unwrap();
    assert!(
        catalog
            .path(omitted)
            .unwrap()
            .values(&value)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        safe["supported_payloads"]["declarations"]["configurations"],
        reported["supported-payloads"]["declarations"]["configurations"]
    );
}
