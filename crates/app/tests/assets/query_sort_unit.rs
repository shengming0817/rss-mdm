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
            actual.sort_by_key(|v| key(Some(&State::Known(v.clone())), descending));
            assert_eq!(actual, expected);
            for value in values.iter() {
                assert!(
                    key(Some(&State::Known(value.clone())), descending)
                        < key(Some(&State::Missing), descending)
                );
            }
        }
    }
    assert_eq!(
        key(Some(&State::Null), false),
        key(Some(&State::Conflict), true)
    );
}
