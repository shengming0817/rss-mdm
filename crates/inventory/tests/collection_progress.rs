use rss_mdm_inventory::{
    CollectedValue, CollectionDefinition, CollectionProgress, Quality, Scalar, Source, builtin,
};
use rss_observation::Body;
fn definition() -> CollectionDefinition {
    CollectionDefinition::new(
        "native-basic",
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
fn status_and_value_must_both_succeed_before_becoming_a_fact() {
    let mut p = CollectionProgress::new(definition());
    p.observe_value(
        builtin::MODEL,
        CollectedValue::Value(Scalar::String("A".into())),
        10,
    )
    .unwrap();
    assert!(matches!(p.body().unwrap(), Some(Body::Partial(v)) if v.is_empty()));
    p.observe_status(builtin::MODEL, 200, 11).unwrap();
    assert!(matches!(p.body().unwrap(),Some(Body::Partial(v)) if v.len()==1));
    p.observe_status(builtin::OS_VERSION, 501, 12).unwrap();
    assert!(matches!(p.body().unwrap(),Some(Body::Snapshot(v)) if v.len()==2));
}
#[test]
fn restored_progress_rejects_changed_values_unknown_keys_and_forged_quality() {
    let mut p = CollectionProgress::new(definition());
    p.observe_status(builtin::MODEL, 200, 10).unwrap();
    p.observe_value(
        builtin::MODEL,
        CollectedValue::Value(Scalar::String("A".into())),
        10,
    )
    .unwrap();
    let mut restored: CollectionProgress =
        serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
    assert!(
        restored
            .observe_value(
                builtin::MODEL,
                CollectedValue::Value(Scalar::String("B".into())),
                11
            )
            .is_err()
    );
    assert!(
        restored
            .observe_status(builtin::OSQUERY_VERSION, 200, 11)
            .is_err()
    );
    let mut doc = serde_json::to_value(p).unwrap();
    doc["fields"][builtin::OS_VERSION.as_str()]["quality"] = serde_json::json!("success");
    assert!(serde_json::from_value::<CollectionProgress>(doc).is_err());
}
#[test]
fn missing_and_failed_fields_never_clear_previous_facts() {
    let mut p = CollectionProgress::new(definition());
    p.finish();
    assert!(p.body().unwrap().is_none());
    assert_eq!(p.fields()[&builtin::MODEL].quality, Quality::Missing);
    let mut p = CollectionProgress::new(definition());
    p.observe_status(builtin::MODEL, 500, 10).unwrap();
    p.finish();
    assert!(matches!(p.body().unwrap(), Some(Body::Failed { .. })));
}
#[test]
fn observation_carries_a_complete_result_reference_even_for_partial_collections() {
    let d = definition();
    let batch = rss_mdm_inventory::CollectionReference::batch(
        rss_observation::Id::new("run").unwrap(),
        3,
        rss_contract::Timepoint::try_from(10).unwrap(),
        &d,
        "a".repeat(64),
    )
    .unwrap();
    assert!(matches!(batch.body(),Body::Snapshot(v) if v.len()==1));
    assert_eq!(
        rss_mdm_inventory::CollectionReference::from_batch(&d, &batch)
            .unwrap()
            .digest(),
        "a".repeat(64)
    );
}

#[test]
fn partial_coverage_never_becomes_complete_just_because_all_named_values_are_present() {
    let d = definition();
    let changes = d
        .fields()
        .iter()
        .map(|f| {
            rss_observation::Change::upsert(
                rss_observation::Id::new(f.key.as_str()).unwrap(),
                CollectedValue::Value(Scalar::String("x".into()))
                    .encode(f)
                    .unwrap(),
            )
        })
        .collect();
    let p = CollectionProgress::reported(d, &Body::Partial(changes), 10).unwrap();
    assert!(matches!(p.body().unwrap(), Some(Body::Partial(_))));
}

#[test]
fn invalid_list_items_are_recorded_without_replacing_previous_list_facts() {
    use rss_mdm_inventory::{FieldKey, Invalid, NativeValue, ValueType};
    let mut field = definition().fields()[0].clone();
    field.key = FieldKey::parse("custom.test_items").unwrap();
    field.value_type = ValueType::Array {
        items: Box::new(ValueType::Integer),
        max_items: 10,
    };
    let def =
        CollectionDefinition::new("list", 1, Source::MdmWindows, vec![field.clone()]).unwrap();
    let outcome = NativeValue::list(
        &field,
        vec![Ok(Scalar::Integer(1)), Err(Invalid::TypeMismatch)],
    )
    .unwrap();
    let progress = CollectionProgress::native(def, [(field.key, outcome)].into(), 10).unwrap();
    assert_eq!(
        progress.fields()[&field.key].items(),
        &[Quality::Success, Quality::Invalid]
    );
    assert_eq!(progress.fields()[&field.key].quality, Quality::Invalid);
    assert!(matches!(
        progress.body().unwrap(),
        Some(Body::Failed { .. })
    ));
    let restored: CollectionProgress =
        serde_json::from_slice(&serde_json::to_vec(&progress).unwrap()).unwrap();
    assert_eq!(progress, restored);
}
