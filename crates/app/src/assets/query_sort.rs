//! Order-preserving scalar keys for immutable query result indexes.
use super::*;
use rss_mdm_inventory::State;
pub(super) fn key(value: Option<&State>, descending: bool) -> Vec<u8> {
    let Some(State::Known(value)) = value else {
        return vec![1];
    };
    let mut payload = match value {
        Scalar::String(value) => {
            let mut result = Vec::with_capacity(value.len() + 2);
            for byte in value.bytes() {
                if byte == 0 {
                    result.extend([0, 255]);
                } else {
                    result.push(byte);
                }
            }
            result.extend([0, 0]);
            result
        }
        Scalar::Integer(value) | Scalar::Time(value) => {
            ((*value as u64) ^ (1 << 63)).to_be_bytes().to_vec()
        }
        Scalar::Boolean(value) => vec![u8::from(*value)],
    };
    if descending {
        for byte in &mut payload {
            *byte = !*byte;
        }
    }
    let mut result = vec![0];
    result.extend(payload);
    result
}
#[cfg(test)]
mod tests {
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
}
