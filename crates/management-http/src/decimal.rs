//! Canonical decimal strings at the product HTTP boundary, never persisted numeric models.
//! ref: serde 1.0.228 serde_core/src/{ser,de}/impls.rs; schemars 1.2.2 src/json_schema_impls/primitives.rs.
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{borrow::Cow, num::NonZeroU64};

// Exact positive decimal range, using only portable JSON Schema/ECMAScript regex syntax.
fn positive_pattern(max: u128) -> String {
    let digits = max.to_string();
    let mut parts = vec![digits.clone()];
    if digits.len() > 1 {
        parts.push(format!("[1-9][0-9]{{0,{}}}", digits.len() - 2));
    }
    for (i, digit) in digits.bytes().enumerate() {
        let lower = if i == 0 { b'1' } else { b'0' };
        if digit > lower {
            parts.push(format!(
                "{}[{}-{}][0-9]{{{}}}",
                &digits[..i],
                char::from(lower),
                char::from(digit - 1),
                digits.len() - i - 1
            ));
        }
    }
    format!("(?:{})", parts.join("|"))
}
fn schema(name: &str, max: u128, negative_max: Option<u128>, zero: bool) -> Schema {
    let mut parts = vec![positive_pattern(max)];
    if zero {
        parts.push("0".into());
    }
    if let Some(max) = negative_max {
        parts.push(format!("-{}", positive_pattern(max)));
    }
    // The final negative lookahead rejects the trailing newline accepted by JavaScript's `$`.
    schemars::json_schema!({"type":"string", "title":name,
        "pattern":format!("^(?:{})(?![\\s\\S])", parts.join("|")),
        "maxLength":max.to_string().len() + usize::from(negative_max.is_some())})
}
macro_rules! decimal {
    ($name:ident, $native:ty, $max:expr, $negative:expr, $zero:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) struct $name(pub(crate) $native);
        impl From<$native> for $name {
            fn from(value: $native) -> Self {
                Self(value)
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                let value: $native = text
                    .parse()
                    .map_err(|_| serde::de::Error::custom("decimal integer out of range"))?;
                if value.to_string() != text {
                    return Err(serde::de::Error::custom("noncanonical decimal integer"));
                }
                Ok(Self(value))
            }
        }
        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                schema(stringify!($name), $max, $negative, $zero)
            }
        }
    };
}
decimal!(
    DecimalI64,
    i64,
    i64::MAX as u128,
    Some(i64::MIN.unsigned_abs() as u128),
    true
);
decimal!(DecimalU64, u64, u64::MAX as u128, None, true);
decimal!(
    DecimalI128,
    i128,
    i128::MAX as u128,
    Some(i128::MIN.unsigned_abs()),
    true
);
decimal!(DecimalU128, u128, u128::MAX, None, true);
decimal!(PositiveU64, NonZeroU64, u64::MAX as u128, None, false);

#[cfg(test)]
mod tests {
    use super::*;
    fn check<T: JsonSchema + Serialize + for<'de> Deserialize<'de>>(good: &[&str], bad: &[&str]) {
        let schema = schemars::schema_for!(T).to_value();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for text in good {
            let value = serde_json::json!(text);
            let decoded: T = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
            assert!(validator.is_valid(&value), "{text}");
        }
        for text in bad
            .iter()
            .copied()
            .chain(["", "+1", "01", "-0", "1.0", "1e2", " 1", "1\n", "１２"])
        {
            let value = serde_json::json!(text);
            assert!(
                serde_json::from_value::<T>(value.clone()).is_err(),
                "{text}"
            );
            assert!(!validator.is_valid(&value), "{text}");
        }
        for value in [
            serde_json::json!(1),
            serde_json::json!(null),
            serde_json::json!(true),
        ] {
            assert!(serde_json::from_value::<T>(value.clone()).is_err());
            assert!(!validator.is_valid(&value));
        }
    }
    #[test]
    fn canonical_native_ranges_match_schema_without_number_fallback() {
        check::<DecimalI64>(
            &[
                "0",
                "-1",
                "9007199254740991",
                "9007199254740993",
                "-9223372036854775808",
                "9223372036854775807",
            ],
            &["-9223372036854775809", "9223372036854775808"],
        );
        check::<DecimalU64>(
            &["0", "9007199254740992", "18446744073709551615"],
            &["-1", "18446744073709551616"],
        );
        check::<DecimalI128>(
            &[
                "0",
                "-170141183460469231731687303715884105728",
                "170141183460469231731687303715884105727",
            ],
            &[
                "-170141183460469231731687303715884105729",
                "170141183460469231731687303715884105728",
            ],
        );
        check::<DecimalU128>(
            &["0", "340282366920938463463374607431768211455"],
            &["-1", "340282366920938463463374607431768211456"],
        );
        check::<PositiveU64>(
            &["1", "18446744073709551615"],
            &["0", "-1", "18446744073709551616"],
        );
    }
}
