use super::*;
#[test]
fn scalar_index_order_preserves_prefix_unicode_numeric_and_unknown_semantics() {
    let lists = vec![
        vec![
            Scalar::String("".into()),
            Scalar::String("a".into()),
            Scalar::String("a\0".into()),
            Scalar::String("aa".into()),
            Scalar::String("é".into()),
            Scalar::String("设备".into()),
        ],
        vec![
            Scalar::Integer(i64::MIN),
            Scalar::Integer(-1),
            Scalar::Integer(0),
            Scalar::Integer(1),
            Scalar::Integer(i64::MAX),
        ],
        vec![Scalar::Boolean(false), Scalar::Boolean(true)],
    ];
    for values in lists {
        for descending in [false, true] {
            let mut expected = values.clone();
            expected.sort();
            if descending {
                expected.reverse();
            }
            let mut actual = values.clone();
            actual.sort_by_key(|v| key(Some(&State::Known(v.clone())), descending).unwrap());
            assert_eq!(actual, expected);
            for value in values.iter() {
                assert!(
                    key(Some(&State::Known(value.clone())), descending).unwrap()
                        < key(Some(&State::Missing), descending).unwrap()
                );
            }
        }
    }
    assert_eq!(
        key(Some(&State::Null), false).unwrap(),
        key(Some(&State::Conflict), true).unwrap()
    );
}

#[test]
fn numeric_sort_preserves_fractional_negative_values_and_canonical_zero() {
    let values: Vec<Scalar> = [-100.5, -2.25, 0.0, 1.5, 10.25]
        .into_iter()
        .map(|n| serde_json::from_value(serde_json::json!({"kind":"number","value":n})).unwrap())
        .collect();
    let keys: Vec<_> = values
        .into_iter()
        .map(|v| key(Some(&State::Known(v)), false).unwrap())
        .collect();
    assert!(keys.windows(2).all(|p| p[0] < p[1]));
    assert!(key(Some(&State::Known(Scalar::Array(vec![]))), false).is_err());
}
