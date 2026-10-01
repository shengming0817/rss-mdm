use super::*;
use rss_mdm_inventory::{CollectedValue, CollectionDefinition, Scalar, Source, builtin};
fn definition() -> CollectionDefinition {
    CollectionDefinition::new(
        "inventory",
        1,
        Source::MdmWindows,
        builtin::fields()
            .into_iter()
            .filter(|f| [builtin::MODEL, builtin::OS_VERSION].contains(&f.key))
            .collect(),
    )
    .unwrap()
}
#[test]
fn native_partial_and_failed_results_preserve_per_field_quality() {
    let attempts = Attempts::native(
        definition(),
        [(
            builtin::MODEL,
            NativeValue::Value(CollectedValue::Value(Scalar::String("Mac".into()))),
        )]
        .into_iter()
        .collect(),
        100,
    )
    .unwrap();
    assert_eq!(attempts.fields()[&builtin::MODEL].quality, Quality::Success);
    assert_eq!(
        attempts.fields()[&builtin::OS_VERSION].quality,
        Quality::Missing
    );
    assert!(attempts.fields().values().all(|f| f.status.is_none()));
    assert!(matches!(attempts.body().unwrap(),Some(Body::Partial(v)) if v.len()==1));
}
#[test]
fn successful_zero_fields_is_distinct_from_failure_and_unattempted() {
    let empty = Attempts::reported(definition(), &Body::Snapshot(vec![]), 100).unwrap();
    assert!(
        empty
            .fields()
            .values()
            .all(|f| f.quality == Quality::Deleted)
    );
    let failed = Attempts::reported(
        definition(),
        &Body::Failed {
            code: Id::new("failed").unwrap(),
        },
        100,
    )
    .unwrap();
    assert!(
        failed
            .fields()
            .values()
            .all(|f| f.quality == Quality::Failed)
    );
    let mut unattempted = Attempts::new(definition());
    unattempted.finish();
    assert!(
        unattempted
            .fields()
            .values()
            .all(|f| f.quality == Quality::Missing)
    );
    assert!(unattempted.body().unwrap().is_none());
}
#[test]
fn legacy_positional_progress_cannot_be_restored() {
    assert!(serde_json::from_str::<Attempts>(r#"{"fields":[{"status":200,"quality":"success","received_at":1,"value":"model","value_digest":null}]}"#).is_err());
}
