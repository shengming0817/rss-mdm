//! Exact decimal strings at the persistent/browser contract boundary; native protocols keep integers.
use serde::{Deserialize, Deserializer, Serializer, de::Error};
pub(super) fn serialize<T: std::fmt::Display, S: Serializer>(
    value: &T,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&value.to_string())
}
pub(super) fn deserialize<'de, T, D>(d: D) -> Result<T, D::Error>
where
    T: std::str::FromStr + std::fmt::Display,
    D: Deserializer<'de>,
{
    let text = String::deserialize(d)?;
    let value: T = text
        .parse()
        .map_err(|_| D::Error::custom("native integer"))?;
    if value.to_string() != text {
        return Err(D::Error::custom("noncanonical native integer"));
    }
    Ok(value)
}
