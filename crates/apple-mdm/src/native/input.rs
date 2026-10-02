//! Persistent Apple-native values. JSON storage must not erase plist Date/Data types.
use super::{Command, Error, Target};
use base64::Engine;
use plist::{Dictionary, Value};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, MapAccess, Visitor},
};
use std::{collections::BTreeMap, fmt};

/// A native dictionary with unique field names and typed values.
#[derive(Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Fields(pub BTreeMap<String, FieldValue>);
impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Unique;
        impl<'de> Visitor<'de> for Unique {
            type Value = Fields;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("unique native fields")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Fields, M::Error> {
                let mut fields = BTreeMap::new();
                while let Some(name) = map.next_key::<String>()? {
                    if fields.len() >= 65_536 || fields.contains_key(&name) {
                        return Err(M::Error::custom("invalid native field map"));
                    }
                    fields.insert(name, map.next_value()?);
                }
                Ok(Fields(fields))
            }
        }
        deserializer.deserialize_map(Unique)
    }
}
/// Native plist atoms, represented explicitly in the new HTTP/persistent contract.
#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum FieldValue {
    /// Unicode text.
    String(String),
    /// Signed plist integer.
    Integer(#[serde(with = "super::decimal")] i64),
    /// Unsigned plist integer outside the signed range.
    Unsigned(#[serde(with = "super::decimal")] u64),
    /// Finite real value.
    Real(f64),
    /// Boolean value.
    Boolean(bool),
    /// RFC3339 plist date.
    Date(String),
    /// Base64-encoded native bytes.
    Data(String),
    /// Ordered native array.
    Array(Vec<FieldValue>),
    /// Nested native dictionary.
    Dictionary(Fields),
}
impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativePlistValue([REDACTED])")
    }
}
struct Budget {
    nodes: usize,
    bytes: usize,
}
impl Budget {
    fn charge(&mut self, bytes: usize, depth: usize) -> Result<(), Error> {
        self.nodes = self.nodes.checked_add(1).ok_or(Error::Limit)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(Error::Limit)?;
        if depth > 64 || self.nodes > 65_536 || self.bytes > 16 * 1024 * 1024 {
            return Err(Error::Limit);
        }
        Ok(())
    }
}
impl Fields {
    /// Convert once at the codec boundary while preserving native scalar types.
    pub fn to_plist(&self) -> Result<Dictionary, Error> {
        self.lower(&mut Budget { nodes: 0, bytes: 0 }, 0)
    }
    fn lower(&self, budget: &mut Budget, depth: usize) -> Result<Dictionary, Error> {
        budget.charge(0, depth)?;
        let mut values = Dictionary::new();
        for (name, value) in &self.0 {
            budget.charge(name.len(), depth)?;
            values.insert(name.clone(), value.lower(budget, depth + 1)?);
        }
        Ok(values)
    }
}
impl FieldValue {
    /// Convert a bounded native value without inferring its type from string contents.
    pub fn to_plist(&self) -> Result<Value, Error> {
        self.lower(&mut Budget { nodes: 0, bytes: 0 }, 0)
    }
    fn lower(&self, budget: &mut Budget, depth: usize) -> Result<Value, Error> {
        budget.charge(0, depth)?;
        Ok(match self {
            Self::String(v) => {
                budget.charge(v.len(), depth)?;
                Value::String(v.clone())
            }
            Self::Integer(v) => Value::Integer((*v).into()),
            Self::Unsigned(v) => Value::Integer((*v).into()),
            Self::Real(v) if v.is_finite() => Value::Real(*v),
            Self::Real(_) => return Err(Error::Constraint),
            Self::Boolean(v) => Value::Boolean(*v),
            Self::Date(v) => {
                budget.charge(v.len(), depth)?;
                Value::Date(plist::Date::from_xml_format(v).map_err(|_| Error::Constraint)?)
            }
            Self::Data(v) => {
                budget.charge(v.len(), depth)?;
                Value::Data(
                    base64::engine::general_purpose::STANDARD
                        .decode(v)
                        .map_err(|_| Error::Constraint)?,
                )
            }
            Self::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|v| v.lower(budget, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            Self::Dictionary(values) => Value::Dictionary(values.lower(budget, depth + 1)?),
        })
    }
}

/// Persistent native command input. UUID, registration, OS evidence and authorization are server-owned.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandInput {
    /// Official native RequestType.
    pub request_type: String,
    /// Command-specific fields; excludes CommandUUID and RequestType envelope keys.
    pub fields: Fields,
}
impl fmt::Debug for CommandInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleCommandInput([REDACTED])")
    }
}
impl CommandInput {
    /// Validate the full generated native contract against server-owned target evidence.
    pub fn compile(&self, target: &Target<'_>) -> Result<Command, Error> {
        Command::new(&self.request_type, self.fields.to_plist()?, target)
    }
}

impl Fields {
    /// Preserve native types with one shared budget checked before copying or descending.
    pub fn from_plist(fields: &Dictionary) -> Result<Self, Error> {
        Self::lift(fields, &mut Budget { nodes: 0, bytes: 0 }, 0)
    }
    fn lift(fields: &Dictionary, budget: &mut Budget, depth: usize) -> Result<Self, Error> {
        budget.charge(0, depth)?;
        let mut converted = BTreeMap::new();
        for (name, value) in fields {
            budget.charge(name.len(), depth)?;
            converted.insert(name.clone(), FieldValue::lift(value, budget, depth + 1)?);
        }
        Ok(Self(converted))
    }
}
impl FieldValue {
    fn lift(value: &Value, budget: &mut Budget, depth: usize) -> Result<Self, Error> {
        budget.charge(0, depth)?;
        Ok(match value {
            Value::String(v) => {
                budget.charge(v.len(), depth)?;
                Self::String(v.clone())
            }
            Value::Boolean(v) => Self::Boolean(*v),
            Value::Integer(v) => {
                if let Some(v) = v.as_signed() {
                    Self::Integer(v)
                } else {
                    Self::Unsigned(v.as_unsigned().ok_or(Error::Field)?)
                }
            }
            Value::Real(v) if v.is_finite() => Self::Real(*v),
            Value::Real(_) => return Err(Error::Constraint),
            Value::Date(v) => {
                let date = v.to_xml_format();
                budget.charge(date.len(), depth)?;
                Self::Date(date)
            }
            Value::Data(v) => {
                let encoded = v
                    .len()
                    .checked_add(2)
                    .and_then(|n| (n / 3).checked_mul(4))
                    .ok_or(Error::Limit)?;
                budget.charge(encoded, depth)?;
                Self::Data(base64::engine::general_purpose::STANDARD.encode(v))
            }
            Value::Array(v) => Self::Array(
                v.iter()
                    .map(|value| Self::lift(value, budget, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Dictionary(v) => Self::Dictionary(Fields::lift(v, budget, depth + 1)?),
            _ => return Err(Error::Field),
        })
    }
}
