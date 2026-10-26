use rss_mdm_inventory::{CollectedValue, NativeValue, Quality, Scalar, ValueType, builtin};
use serde_json::{Value, json};

fn field() -> rss_mdm_inventory::FieldDefinition {
    builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.software.installations")
        .unwrap()
}
fn item(origin: &str, state: &str, scope: &str, owner: &str) -> Value {
    json!({"id":format!("{origin}:{owner}"),"native_id":"same-package","name":"App","version":"1","publisher":"Vendor","scope":scope,"owner":owner,"origin":origin,"location":"","installation_state":state})
}
fn decode(value: &Value) -> Scalar {
    let ValueType::Array { items, .. } = field().value_type else {
        unreachable!()
    };
    items.decode_json(value).unwrap()
}

#[test]
fn software_states_are_required_and_consistent_with_origin_and_owner() {
    let field = field();
    let sid = "S-1-5-21-1-2-3-1001";
    for (origin, state, scope, owner) in [
        ("win32.uninstall.32", "installed", "device", ""),
        ("win32.uninstall.64", "installed", "user", sid),
        ("msix.registered", "registered", "user", sid),
        ("msix.provisioned", "provisioned", "device", ""),
        ("application", "installed", "user", "501"),
    ] {
        let row = item(origin, state, scope, owner);
        assert!(
            field
                .validate_scalar(&Scalar::Array(vec![decode(&row)]))
                .is_ok()
        );
    }
    for (origin, state, scope, owner) in [
        ("msix.registered", "installed", "user", sid),
        ("msix.registered", "registered", "device", ""),
        ("msix.registered", "registered", "user", "user-name"),
        ("msix.provisioned", "provisioned", "user", sid),
        ("msix.provisioned", "provisioned", "device", sid),
        ("msix.typo", "installed", "device", ""),
        ("win32.uninstall.128", "installed", "device", ""),
        ("application", "provisioned", "device", ""),
        ("application", "installed", "user", ""),
    ] {
        let row = decode(&item(origin, state, scope, owner));
        let value = CollectedValue::Value(Scalar::Array(vec![row]));
        assert!(
            value.encode(&field).is_err(),
            "{origin}/{state}/{scope}/{owner}"
        );
    }
    let mut old = item("application", "installed", "device", "");
    old.as_object_mut().unwrap().remove("installation_state");
    assert!(field.value_type.decode_json(&json!([old.clone()])).is_err());
    for key in ["device.software.receipts", "device.software.packages"] {
        let field = builtin::fields()
            .into_iter()
            .find(|f| f.key.as_str() == key)
            .unwrap();
        assert!(field.value_type.decode_json(&json!([old.clone()])).is_ok());
    }
}

#[test]
fn invalid_software_rows_preserve_quality_and_never_publish_a_partial_list() {
    let field = field();
    let valid = decode(&item("msix.provisioned", "provisioned", "device", ""));
    let invalid = decode(&item("msix.provisioned", "registered", "device", ""));
    assert!(
        matches!(NativeValue::list(&field, vec![Ok(valid.clone()), Ok(invalid)]).unwrap(),
        NativeValue::InvalidItems { items: q, .. } if q == vec![Quality::Success, Quality::Invalid])
    );
    assert!(
        matches!(NativeValue::list(&field, vec![Ok(valid.clone()), Ok(valid.clone())]).unwrap(),
        NativeValue::InvalidItems { items: q, .. } if q == vec![Quality::Invalid, Quality::Invalid])
    );
    let registered = decode(&item(
        "msix.registered",
        "registered",
        "user",
        "S-1-5-21-1-2-3-1001",
    ));
    let second = decode(&item(
        "msix.registered",
        "registered",
        "user",
        "S-1-5-21-1-2-3-1002",
    ));
    assert!(
        matches!(NativeValue::list(&field, vec![Ok(valid), Ok(registered), Ok(second)]).unwrap(),
        NativeValue::Value(CollectedValue::Value(Scalar::Array(rows))) if rows.len() == 3)
    );
    assert!(matches!(NativeValue::list(&field, vec![]).unwrap(),
        NativeValue::Value(CollectedValue::Value(Scalar::Array(rows))) if rows.is_empty()));
}

#[test]
fn apple_optional_identifiers_and_repeated_bundles_do_not_reduce_coverage() {
    use rss_mdm_inventory::{
        CollectionDefinition, CollectionField, CollectionProgress, CollectionScope, Source,
    };
    use rss_observation::Body;
    let field = builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.software.apple.installed_applications")
        .unwrap();
    assert!(field.item_key.is_none());
    let ValueType::Array { items, .. } = &field.value_type else {
        unreachable!()
    };
    let rows = json!([
        {"id":"com.example.valid", "name":"Valid application"},
        {"name":"Anonymous application", "path":"/Applications/Anonymous.app"},
        {"id":"com.example.duplicate", "name":"First copy", "path":"/Applications/First.app"},
        {"id":"com.example.duplicate", "name":"Second copy", "path":"/Applications/Second.app"},
        {},
        {"id":"", "path":""},
        {"id":"com.example.last", "name":"Last application"}
    ]);
    let definition = CollectionDefinition::new(
        "apple-apps",
        1,
        Source::MdmApple,
        vec![CollectionField {
            definition: field.clone(),
            scope: CollectionScope::Device,
        }],
    )
    .unwrap();
    let outcome = || {
        NativeValue::list(
            &field,
            rows.as_array()
                .unwrap()
                .iter()
                .map(|v| items.decode_json(v))
                .collect(),
        )
        .unwrap()
    };
    let progress =
        CollectionProgress::native(definition.clone(), [(field.key, outcome())].into(), 10)
            .unwrap();
    assert!(progress.coverage_complete());
    assert_eq!(progress.fields()[&field.key].quality, Quality::Success);
    assert_eq!(
        progress.fields()[&field.key].items(),
        &[Quality::Success; 7]
    );
    assert!(matches!(progress.body().unwrap(), Some(Body::Snapshot(_))));
    let restored: CollectionProgress =
        serde_json::from_value(serde_json::to_value(&progress).unwrap()).unwrap();
    assert_eq!(progress, restored);
    let NativeValue::Value(CollectedValue::Value(value)) = outcome() else {
        panic!("valid list rejected")
    };
    assert_eq!(value, field.value_type.decode_json(&rows).unwrap());
    let partial =
        CollectionProgress::native_partial(definition.clone(), [(field.key, outcome())].into(), 10)
            .unwrap();
    assert!(!partial.coverage_complete());
    assert!(matches!(partial.body().unwrap(), Some(Body::Partial(_))));
    let invalid = NativeValue::list(
        &field,
        vec![
            items.decode_json(&rows[1]),
            items.decode_json(&json!({"id":42})),
        ],
    )
    .unwrap();
    let invalid =
        CollectionProgress::native(definition.clone(), [(field.key, invalid)].into(), 10).unwrap();
    assert!(!invalid.coverage_complete());
    assert_eq!(
        invalid.fields()[&field.key].items(),
        &[Quality::Success, Quality::Invalid]
    );
    assert!(matches!(invalid.body().unwrap(), Some(Body::Failed { .. })));
    let empty = NativeValue::list(&field, vec![]).unwrap();
    let empty = CollectionProgress::native(definition, [(field.key, empty)].into(), 10).unwrap();
    assert!(empty.coverage_complete());
    assert!(matches!(empty.body().unwrap(), Some(Body::Snapshot(_))));
}

#[test]
fn apple_application_properties_are_typed_and_identity_lists_still_require_keys() {
    let fields = builtin::fields();
    let apps = fields
        .iter()
        .find(|f| f.key.as_str() == "device.software.apple.installed_applications")
        .unwrap();
    for row in [
        json!({"id":42}),
        json!({"path":false}),
        json!({"path":"x".repeat(4097)}),
        json!({"id":null}),
    ] {
        assert!(apps.value_type.decode_json(&json!([row])).is_err());
    }
    assert!(
        apps.value_type
            .decode_json(&json!([{"path":"x".repeat(4096)}]))
            .is_ok()
    );
    // Exercise list overflow with a small declared budget, not a large allocation.
    let mut bounded = apps.clone();
    let ValueType::Array { max_items, .. } = &mut bounded.value_type else {
        unreachable!()
    };
    *max_items = 1;
    assert!(matches!(
        NativeValue::list(&bounded, vec![Ok(Scalar::Object(Default::default())); 2]).unwrap(),
        NativeValue::Invalid
    ));
    for key in [
        "device.management.apple.managed_profiles",
        "device.security.apple.managed_certificates",
        "device.management.apple.users",
    ] {
        let field = fields.iter().find(|f| f.key.as_str() == key).unwrap();
        assert_eq!(field.item_key.as_deref(), Some("id"));
        for row in [json!({}), json!({"id":""})] {
            assert!(field.value_type.decode_json(&json!([row])).is_err());
        }
        let duplicates = field
            .value_type
            .decode_json(&json!([{"id":"same"},{"id":"same"}]))
            .unwrap();
        assert!(field.validate_scalar(&duplicates).is_err());
    }
}
