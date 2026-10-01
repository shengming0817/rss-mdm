use rss_mdm_inventory::*;
use rss_observation::{Batch, Body, Change, Id};
#[test]
fn typed_collection_rejects_unknown_fields_invalid_values_and_legacy_text() {
    let catalog = Catalog::new(builtin::fields()).unwrap();
    let field = catalog.definition(builtin::MODEL).unwrap();
    let contract =
        CollectionDefinition::new("device-basics", 1, Source::MdmWindows, vec![field.clone()])
            .unwrap();
    for (key, value) in [
        ("password", b"x".to_vec()),
        ("device.model", vec![]),
        ("device.model", vec![255]),
    ] {
        let batch = Batch::new(
            Id::new("b").unwrap(),
            0,
            rss_contract::Timepoint::try_from(100).unwrap(),
            contract.coverage().unwrap(),
            Body::Snapshot(vec![Change::upsert(Id::new(key).unwrap(), value)]),
        )
        .unwrap();
        assert!(contract.validate(&batch).is_err());
    }
    let value = CollectedValue::Value(Scalar::String("Model".into()))
        .encode(field)
        .unwrap();
    let batch = Batch::new(
        Id::new("b").unwrap(),
        0,
        rss_contract::Timepoint::try_from(100).unwrap(),
        contract.coverage().unwrap(),
        Body::Partial(vec![Change::upsert(
            Id::new(field.key.as_str()).unwrap(),
            value,
        )]),
    )
    .unwrap();
    assert!(contract.validate(&batch).is_ok());
    let bytes = CollectedValue::Unsupported.encode(field).unwrap();
    assert_eq!(
        CollectedValue::decode(field, &bytes).unwrap(),
        CollectedValue::Unsupported
    );
    assert!(CollectedValue::decode(field, b"legacy").is_err());
    assert!(
        CollectedValue::Value(Scalar::String("".into()))
            .encode(field)
            .is_err()
    );
}
