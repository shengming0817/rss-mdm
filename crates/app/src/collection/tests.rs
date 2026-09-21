use super::*;

#[test]
fn fragments_require_successful_status_and_valid_values_for_both_fields() {
    let mut attempt = Attempts::default();
    attempt.status(0, 200).unwrap();
    attempt.value(0, "Model-A".into()).unwrap();
    assert!(!attempt.complete());
    assert!(matches!(
        attempt.body(),
        Some(rss_observation::Body::Partial(_))
    ));
    attempt.value(1, "10.0.26100".into()).unwrap();
    assert!(!attempt.complete());
    attempt.status(1, 200).unwrap();
    assert!(attempt.complete());
    assert!(matches!(
        attempt.body(),
        Some(rss_observation::Body::Snapshot(_))
    ));
}

#[test]
fn timeout_without_report_has_no_observation_body() {
    let mut attempt = Attempts::default();
    attempt.finish();
    assert!(attempt.body().is_none());
    assert_eq!(attempt.fields[0].quality, Quality::Missing);
}

#[test]
fn unconfirmed_values_remain_partial_and_invalid_input_is_bounded() {
    let mut attempt = Attempts::default();
    attempt.value(0, "A".into()).unwrap();
    attempt.value(1, "10".into()).unwrap();
    attempt.finish();
    assert!(matches!(
        attempt.body(),
        Some(rss_observation::Body::Partial(_))
    ));
    let mut attempt = Attempts::default();
    attempt.value(0, "\u{0001}".repeat(4096)).unwrap();
    assert_eq!(attempt.fields[0].quality, Quality::Invalid);
    assert!(serde_json::to_string(&attempt).unwrap().len() < 2048);
}

#[test]
fn failures_never_overwrite_last_good_values() {
    let mut attempt = Attempts::default();
    attempt.status(0, 404).unwrap();
    attempt.status(1, 500).unwrap();
    assert!(attempt.complete());
    assert!(matches!(
        attempt.body(),
        Some(rss_observation::Body::Failed { .. })
    ));
    assert!(attempt.value(0, "contradiction".into()).is_err());

    let mut attempt = Attempts::default();
    attempt.status(0, 200).unwrap();
    attempt.value(0, "  ".into()).unwrap();
    attempt.status(1, 200).unwrap();
    attempt.value(1, "10".into()).unwrap();
    assert!(attempt.complete());
    assert_eq!(attempt.fields[0].quality, Quality::Invalid);
    assert!(matches!(
        attempt.body(),
        Some(rss_observation::Body::Partial(_))
    ));
}

#[test]
fn persisted_fragments_reject_changed_facts() {
    let mut attempt = Attempts::default();
    attempt.value(0, "A".into()).unwrap();
    let mut recovered: Attempts =
        serde_json::from_str(&serde_json::to_string(&attempt).unwrap()).unwrap();
    assert!(recovered.value(0, "B".into()).is_err());
    assert!(recovered.status(0, 404).is_err());
    recovered.status(0, 200).unwrap();
    assert_eq!(recovered.fields[0].quality, Quality::Success);
}

#[test]
fn command_range_covers_catalog_and_rejects_outside_without_overflow() {
    let first = u32::MAX - FIELD_COUNT as u32 + 1;
    for (index, key) in FieldKey::observed().enumerate() {
        assert_eq!(field_index(first + index as u32, first), Some(index));
        assert!(uri(key).starts_with("./"));
    }
    assert_eq!(field_index(first - 1, first), None);
    assert_eq!(field_index(1024 + FIELD_COUNT as u32, 1024), None);
}
