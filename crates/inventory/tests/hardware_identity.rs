use rss_mdm_inventory::{
    CollectedValue, Scalar, builtin, normalize_hardware_uuid, normalize_serial_number,
};

#[test]
fn protected_identity_fields_reject_placeholders_in_every_encoded_report() {
    for (key, invalid) in [
        (
            "device.serial_number",
            vec![
                "",
                "  ",
                "0000",
                "  unknown ",
                "To Be Filled By O.E.M.",
                "NULL",
                "N/A",
                "bad\u{0007}serial",
            ],
        ),
        (
            "device.hardware_uuid",
            vec![
                "not-a-uuid",
                "00000000-0000-0000-0000-000000000000",
                "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
                "03000200-0400-0500-0006-000700080009",
            ],
        ),
    ] {
        let field = builtin::fields()
            .into_iter()
            .find(|f| f.key.as_str() == key)
            .unwrap();
        for raw in invalid {
            let value = CollectedValue::Value(Scalar::String(raw.into()));
            assert!(value.encode(&field).is_err(), "{key}: {raw:?}");
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(CollectedValue::decode(&field, &bytes).is_err());
        }
    }
}

#[test]
fn normalization_is_idempotent_without_rewriting_received_evidence() {
    for (key, raw, expected) in [
        ("device.serial_number", "  ab-c.123  ", "AB-C.123"),
        (
            "device.hardware_uuid",
            "{12345678-ABCD-4234-ABCD-123456789ABC}",
            "12345678-abcd-4234-abcd-123456789abc",
        ),
    ] {
        let field = builtin::fields()
            .into_iter()
            .find(|f| f.key.as_str() == key)
            .unwrap();
        let raw_value = Scalar::String(raw.into());
        let encoded = CollectedValue::Value(raw_value.clone())
            .encode(&field)
            .unwrap();
        let canonical = field.canonical_value(raw_value.clone()).unwrap();
        assert_eq!(canonical, Scalar::String(expected.into()));
        assert_eq!(field.canonical_value(canonical.clone()).unwrap(), canonical);
        assert_eq!(
            CollectedValue::decode(&field, &encoded).unwrap(),
            CollectedValue::Value(raw_value)
        );
    }
    assert_eq!(normalize_serial_number(" ab-1 ").unwrap(), "AB-1");
    assert_eq!(
        normalize_hardware_uuid("12345678-ABCD-4234-ABCD-123456789ABC").unwrap(),
        "12345678-abcd-4234-abcd-123456789abc"
    );
}
