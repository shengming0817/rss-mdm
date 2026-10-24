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
fn apple_anonymous_and_duplicate_rows_retain_only_unambiguous_evidence() {
    let field = builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.software.apple.installed_applications")
        .unwrap();
    let ValueType::Array { items, .. } = &field.value_type else {
        unreachable!()
    };
    let rows = [
        json!({"id":"com.example.valid", "name":"Valid application"}),
        json!({"name":"Anonymous application"}),
        json!({"id":"com.example.duplicate", "name":"First copy"}),
        json!({"id":"com.example.duplicate", "name":"Second copy"}),
        json!({"id":"com.example.last", "name":"Last application"}),
    ];
    let outcome =
        NativeValue::list(&field, rows.iter().map(|v| items.decode_json(v)).collect()).unwrap();
    let NativeValue::InvalidItems {
        items: quality,
        values,
    } = outcome
    else {
        panic!("incomplete list accepted")
    };
    assert_eq!(
        quality,
        [
            Quality::Success,
            Quality::Invalid,
            Quality::Invalid,
            Quality::Invalid,
            Quality::Success
        ]
    );
    assert_eq!(
        values,
        vec![
            items.decode_json(&rows[0]).unwrap(),
            items.decode_json(&rows[4]).unwrap()
        ]
    );
}
