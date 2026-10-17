use rss_mdm_resource::{Conversion, ValueMapping};
use serde_json::json;

#[test]
fn native_codes_are_explicit_and_unknown_values_fail() {
    let conversion = Conversion::Enum {
        values: [
            ("0".into(), json!("unprotected")),
            ("1".into(), json!("protected")),
            ("2".into(), json!("unknown")),
        ]
        .into(),
    };
    assert_eq!(conversion.apply(&json!(1)).unwrap(), json!("protected"));
    assert_eq!(conversion.apply(&json!("2")).unwrap(), json!("unknown"));
    assert!(conversion.apply(&json!(3)).is_err());
    assert!(conversion.apply(&json!(true)).is_err());
}
#[test]
fn units_reject_negative_overflow_and_fractional_results() {
    let bytes = Conversion::Scale {
        numerator: 1024,
        denominator: 1,
    };
    assert_eq!(bytes.apply(&json!("2048")).unwrap(), json!(2097152));
    assert!(bytes.apply(&json!(-1)).is_err());
    assert!(bytes.apply(&json!(i64::MAX)).is_err());
    assert!(
        Conversion::Scale {
            numerator: 1,
            denominator: 1000
        }
        .apply(&json!(1001))
        .is_err()
    );
    assert!(Conversion::Number.apply(&json!("NaN")).is_err());
}
#[test]
fn bitmasks_reject_unknown_bits_and_duplicate_labels() {
    let flags = Conversion::Bitmask {
        flags: [("1".into(), "a".into()), ("4".into(), "b".into())].into(),
    };
    assert_eq!(flags.apply(&json!(5)).unwrap(), json!(["a", "b"]));
    assert_eq!(flags.apply(&json!(0)).unwrap(), json!([]));
    assert!(flags.apply(&json!(2)).is_err());
    assert!(
        Conversion::Bitmask {
            flags: [("1".into(), "a".into()), ("2".into(), "a".into())].into()
        }
        .validate()
        .is_err()
    );
}
#[test]
fn list_columns_are_explicit_typed_and_bounded() {
    let mapping = ValueMapping {
        pointer: "".into(),
        conversion: Conversion::Identity,
        columns: [
            ("id".into(), ValueMapping::identity("/device_id")),
            (
                "size_bytes".into(),
                ValueMapping {
                    pointer: "/size".into(),
                    conversion: Conversion::Integer,
                    columns: Default::default(),
                },
            ),
        ]
        .into(),
    };
    mapping.validate().unwrap();
    assert_eq!(
        mapping
            .project(&json!({"device_id":"C:","size":"2048","secret":"hidden"}))
            .unwrap(),
        json!({"id":"C:","size_bytes":2048})
    );
    assert!(mapping.project(&json!({"device_id":"C:"})).is_err());
    assert!(ValueMapping::identity("/bad~2escape").validate().is_err());
    assert!(serde_json::from_value::<ValueMapping>(json!("/old-format")).is_err());
}

#[test]
fn cim_time_requires_full_date_and_offset_and_normalizes_to_utc() {
    assert_eq!(
        Conversion::CimTime
            .apply(&json!("20261015120000.000000+060"))
            .unwrap(),
        json!(1792062000i64)
    );
    for v in [
        "20261015120000.000000+***",
        "20261315120000.000000+000",
        "00000001000000.000000:000",
        "20261015120000.000000",
    ] {
        assert!(Conversion::CimTime.apply(&json!(v)).is_err());
    }
}

#[test]
fn unsigned_scaling_checks_the_output_range_without_losing_input_precision() {
    assert_eq!(
        Conversion::Scale {
            numerator: 1,
            denominator: 3
        }
        .apply(&json!(u64::MAX.to_string()))
        .unwrap(),
        json!(6148914691236517205i64)
    );
    assert!(
        Conversion::Scale {
            numerator: 1,
            denominator: 2
        }
        .apply(&json!(u64::MAX.to_string()))
        .is_err()
    );
    assert!(
        Conversion::Scale {
            numerator: 1,
            denominator: 1
        }
        .apply(&json!(u64::MAX.to_string()))
        .is_err()
    );
}

#[test]
fn device_guard_array_membership_is_not_a_bitmask_or_nonempty_test() {
    let map = Conversion::ArrayMember {
        member: 2,
        present: serde_json::json!("enabled"),
        absent: serde_json::json!("disabled"),
    };
    assert_eq!(
        map.apply(&serde_json::json!([1])).unwrap(),
        serde_json::json!("disabled")
    );
    assert_eq!(
        map.apply(&serde_json::json!([2, 3])).unwrap(),
        serde_json::json!("enabled")
    );
    assert_eq!(
        map.apply(&serde_json::json!([])).unwrap(),
        serde_json::json!("disabled")
    );
    assert!(map.apply(&serde_json::json!(2)).is_err());
    assert!(map.apply(&serde_json::json!(["2"])).is_err());
}
