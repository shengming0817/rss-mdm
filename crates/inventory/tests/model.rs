use rss_mdm_inventory::{coverage, validate};
use rss_observation::{Batch, Body, Change, Id};
#[test]
fn rejects_unknown_fields_and_invalid_values() {
    for (key, value) in [
        ("password", b"x".as_slice()),
        ("device.model", b""),
        ("device.model", &[255]),
    ] {
        let b = Batch::new(
            Id::new("b").unwrap(),
            0,
            rss_contract::Timepoint::try_from(100).unwrap(),
            coverage(),
            Body::Snapshot(vec![Change::upsert(Id::new(key).unwrap(), value.to_vec())]),
        )
        .unwrap();
        assert!(validate(&b).is_err());
    }
    let b = Batch::new(
        Id::new("b").unwrap(),
        0,
        rss_contract::Timepoint::try_from(100).unwrap(),
        coverage(),
        Body::Partial(vec![Change::upsert(
            Id::new("device.model").unwrap(),
            rss_mdm_inventory::CollectedValue::Known("Model".into())
                .encode(rss_mdm_inventory::FieldKey::Model)
                .unwrap(),
        )]),
    )
    .unwrap();
    assert!(validate(&b).is_ok());
    use rss_mdm_inventory::{CollectedValue, FieldKey};
    let bytes = CollectedValue::Unsupported.encode(FieldKey::Model).unwrap();
    assert_eq!(
        CollectedValue::decode(FieldKey::Model, &bytes).unwrap(),
        CollectedValue::Unsupported
    );
    assert!(CollectedValue::decode(FieldKey::Model, b"legacy").is_err());
    assert!(
        CollectedValue::Known("".into())
            .encode(FieldKey::Model)
            .is_err()
    );
    assert!(
        CollectedValue::Unsupported
            .encode(FieldKey::AssetTag)
            .is_err()
    );
}
