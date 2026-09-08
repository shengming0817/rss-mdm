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
            b"Model".to_vec(),
        )]),
    )
    .unwrap();
    assert!(validate(&b).is_ok());
}
