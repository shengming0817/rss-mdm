//! Tenant-owned, versioned field definitions. Identity alone confers no source authority.
use crate::{Invalid, Result, Scalar, Source};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Current product dictionary contract; catalog revisions are separate business versions.
pub const DICTIONARY: &str = "assets-v2";
/// Validated field identity. Admission requires lookup in the tenant's catalog.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldKey {
    bytes: [u8; 128],
    length: u8,
}
impl std::fmt::Debug for FieldKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FieldKey").field(&self.as_str()).finish()
    }
}
impl FieldKey {
    pub(crate) const fn literal(value: &str) -> Self {
        assert!(value.len() <= 128);
        let mut bytes = [0; 128];
        let mut i = 0;
        while i < value.len() {
            bytes[i] = value.as_bytes()[i];
            i += 1;
        }
        Self {
            bytes,
            length: value.len() as u8,
        }
    }
    /// Validate a bounded, namespaced ASCII key without consulting a catalog.
    pub fn parse(value: &str) -> Result<Self> {
        let mut parts = value.split('.');
        if value.len() > 128 || !matches!(parts.next(), Some("device" | "custom" | "channel")) {
            return Err(Invalid::UnknownField);
        }
        let mut count = 0;
        for part in parts {
            if part.is_empty()
                || !part.as_bytes()[0].is_ascii_lowercase()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(Invalid::UnknownField);
            }
            count += 1;
        }
        if count == 0 {
            return Err(Invalid::UnknownField);
        }
        let mut bytes = [0; 128];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            length: value.len() as u8,
        })
    }
    /// Borrow the exact validated spelling; keys are never normalized.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..usize::from(self.length)])
            .expect("private field identity contains validated ASCII")
    }
}
impl Serialize for FieldKey {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for FieldKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
/// Closed primitive kinds; values never undergo implicit type conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// UTF-8 text.
    String,
    /// Signed integer.
    Integer,
    /// Finite floating-point number.
    Number,
    /// Boolean.
    Boolean,
    /// UTC seconds.
    Time,
    /// Ordered bounded collection.
    Array,
    /// Declared structured properties.
    Object,
}
/// Closed structural schema for one field; every property is explicit and required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ValueType {
    /// Bounded text; empty text is a legitimate value when allowed.
    String {
        /// Character budget.
        max_length: u32,
        /// Whether empty text is allowed.
        allow_empty: bool,
    },
    /// Closed string vocabulary.
    Enum {
        /// Permitted nonempty values.
        values: BTreeSet<String>,
    },
    /// Signed 64-bit integer.
    Integer,
    /// Finite numeric value.
    Number,
    /// Boolean.
    Boolean,
    /// UTC Unix seconds.
    Time,
    /// Ordered values sharing one schema.
    Array {
        /// Element schema.
        items: Box<ValueType>,
        /// Maximum number of values.
        max_items: u32,
    },
    /// Closed properties; undeclared and absent properties are rejected.
    Object {
        /// Property schema by literal name.
        properties: BTreeMap<String, ValueType>,
    },
}
impl ValueType {
    /// Primitive/collection discriminant.
    pub fn kind(&self) -> Kind {
        match self {
            Self::String { .. } | Self::Enum { .. } => Kind::String,
            Self::Integer => Kind::Integer,
            Self::Number => Kind::Number,
            Self::Boolean => Kind::Boolean,
            Self::Time => Kind::Time,
            Self::Array { .. } => Kind::Array,
            Self::Object { .. } => Kind::Object,
        }
    }
    /// Bound both schema depth and its cumulative node count.
    pub fn validate(&self) -> Result<()> {
        self.check(0, &mut 0)
    }
    fn check(&self, depth: usize, nodes: &mut usize) -> Result<()> {
        *nodes += 1;
        if depth > 4 || *nodes > 128 {
            return Err(Invalid::Value);
        }
        match self {
            Self::String { max_length, .. } if !(1..=65536).contains(max_length) => {
                Err(Invalid::Value)
            }
            Self::Enum { values } => {
                if values.is_empty()
                    || values.len() > 128
                    || values
                        .iter()
                        .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
                {
                    Err(Invalid::Value)
                } else {
                    Ok(())
                }
            }
            Self::Array { items, max_items } => {
                if !(1..=100000).contains(max_items) {
                    return Err(Invalid::Value);
                }
                items.check(depth + 1, nodes)
            }
            Self::Object { properties } => {
                if properties.is_empty() || properties.len() > 64 {
                    return Err(Invalid::Value);
                }
                for (key, value) in properties {
                    if !property(key) {
                        return Err(Invalid::Value);
                    }
                    value.check(depth + 1, nodes)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    /// Validate a typed value against exactly this schema.
    pub fn validate_value(&self, value: &Scalar) -> Result<()> {
        value.validate()?;
        match (self, value) {
            (
                Self::String {
                    max_length,
                    allow_empty,
                },
                Scalar::String(s),
            ) if (*allow_empty || !s.is_empty()) && s.chars().count() <= *max_length as usize => {
                Ok(())
            }
            (Self::Enum { values }, Scalar::String(s)) if values.contains(s) => Ok(()),
            (Self::Integer, Scalar::Integer(_))
            | (Self::Number, Scalar::Number(_))
            | (Self::Boolean, Scalar::Boolean(_))
            | (Self::Time, Scalar::Time(_)) => Ok(()),
            (Self::Array { items, max_items }, Scalar::Array(values))
                if values.len() <= *max_items as usize =>
            {
                values.iter().try_for_each(|v| items.validate_value(v))
            }
            (Self::Object { properties }, Scalar::Object(values))
                if properties.len() == values.len() =>
            {
                properties.iter().try_for_each(|(k, t)| {
                    t.validate_value(values.get(k).ok_or(Invalid::TypeMismatch)?)
                })
            }
            _ => Err(Invalid::TypeMismatch),
        }
    }
}
fn property(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key.as_bytes()[0].is_ascii_lowercase()
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
/// Product condition operators. Structured paths are resolved against the same schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Included in a set.
    In,
    /// Excluded from a set.
    NotIn,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Literal substring.
    Contains,
    /// No literal substring.
    NotContains,
    /// Set intersects.
    ContainsAny,
    /// Set contains all.
    ContainsAll,
    /// Explicit null.
    IsNull,
    /// Known value.
    IsNotNull,
}
/// Platform applicable to a field or collector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
}
/// Field visibility class, enforced by the product authorization boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Ordinary inventory.
    Standard,
    /// Requires the sensitive inventory permission.
    Sensitive,
}
/// A published field version. No time-based expiry and no execution permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldDefinition {
    /// Stable field identity.
    pub key: FieldKey,
    /// Monotonic published version.
    pub version: u64,
    /// Exact bounded type.
    pub value_type: ValueType,
    /// Accept explicit null as distinct from deletion.
    pub nullable: bool,
    /// Whether management assignment is permitted.
    pub manual: bool,
    /// Allowed sources with priority; lower numbers win, equal numbers require consensus.
    pub sources: BTreeMap<Source, u16>,
    /// Supported platforms.
    pub platforms: BTreeSet<Platform>,
    /// Read/filter visibility classification.
    pub sensitivity: Sensitivity,
    /// Exact optional unit; no implicit conversion.
    pub unit: Option<String>,
    /// Whether this field participates in conditions/search.
    pub searchable: bool,
    /// Optional stable item-key property for a structured inventory list.
    pub item_key: Option<String>,
}
impl FieldDefinition {
    /// Validate definitions before publication or reconstruction.
    pub fn validate(&self) -> Result<()> {
        self.value_type.validate()?;
        if self.version == 0
            || self.version > i64::MAX as u64
            || self.sources.is_empty()
            || self.platforms.is_empty()
            || self.manual != self.sources.contains_key(&Source::Manual)
            || self
                .unit
                .as_ref()
                .is_some_and(|u| u.is_empty() || u.len() > 64 || u.chars().any(char::is_control))
        {
            return Err(Invalid::Value);
        }
        if let Some(key) = &self.item_key {
            let ValueType::Array { items, .. } = &self.value_type else {
                return Err(Invalid::TypeMismatch);
            };
            let ValueType::Object { properties } = items.as_ref() else {
                return Err(Invalid::TypeMismatch);
            };
            if !matches!(
                properties.get(key),
                Some(
                    ValueType::String {
                        allow_empty: false,
                        ..
                    } | ValueType::Integer
                )
            ) {
                return Err(Invalid::TypeMismatch);
            }
        }
        Ok(())
    }
    /// Validate a value and unique, stable item identities for a declared list.
    pub fn validate_scalar(&self, value: &Scalar) -> Result<()> {
        self.value_type.validate_value(value)?;
        if let (Some(key), Scalar::Array(items)) = (&self.item_key, value) {
            let mut identities = BTreeSet::new();
            for item in items {
                let Scalar::Object(properties) = item else {
                    return Err(Invalid::TypeMismatch);
                };
                if !identities.insert(properties.get(key).ok_or(Invalid::Value)?) {
                    return Err(Invalid::Value);
                }
            }
        }
        Ok(())
    }
    /// Stable identity order for keyed inventories; ordinary arrays remain ordered values.
    pub fn canonical_value(&self, mut value: Scalar) -> Result<Scalar> {
        self.validate_scalar(&value)?;
        if let (Some(key), Scalar::Array(items)) = (&self.item_key, &mut value) {
            items.sort_by(|a, b| match (a, b) {
                (Scalar::Object(a), Scalar::Object(b)) => a.get(key).cmp(&b.get(key)),
                _ => unreachable!("validated keyed list"),
            });
        }
        Ok(value)
    }
    /// Allowed operators are derived from the type, never a second editable dictionary.
    pub fn operations(&self) -> Vec<Operator> {
        use Operator::*;
        if !self.searchable
            || matches!(&self.value_type, ValueType::Object { .. })
            || matches!(&self.value_type,ValueType::Array {items,..} if matches!(items.as_ref(),ValueType::Object {..}|ValueType::Array {..}))
        {
            return Vec::new();
        }
        let mut operations = match self.value_type {
            ValueType::Array { .. } => vec![ContainsAny, ContainsAll],
            ValueType::Object { .. } => Vec::new(),
            _ => vec![Eq, Ne, In, NotIn],
        };
        match self.value_type.kind() {
            Kind::String if !matches!(self.value_type, ValueType::Enum { .. }) => {
                operations.extend([Contains, NotContains])
            }
            Kind::Integer | Kind::Number | Kind::Time => operations.extend([Lt, Le, Gt, Ge]),
            _ => (),
        }
        if self.nullable {
            operations.extend([IsNull, IsNotNull]);
        }
        operations
    }
}
/// A validated tenant catalog snapshot; definition presence is required for admission.
#[derive(Clone, Debug)]
pub struct Catalog {
    fields: BTreeMap<FieldKey, FieldDefinition>,
}
impl Catalog {
    /// Construct one bounded snapshot. Duplicate definitions cannot shadow one another.
    pub fn new(definitions: Vec<FieldDefinition>) -> Result<Self> {
        if definitions.is_empty() || definitions.len() > 1024 {
            return Err(Invalid::Value);
        }
        let mut fields = BTreeMap::new();
        for definition in definitions {
            definition.validate()?;
            if fields.insert(definition.key, definition).is_some() {
                return Err(Invalid::DuplicateField);
            }
        }
        for key in fields.keys() {
            let name = key.as_str();
            for (index, _) in name.match_indices('.') {
                if let Ok(parent) = FieldKey::parse(&name[..index]) {
                    if fields.contains_key(&parent) {
                        return Err(Invalid::DuplicateField);
                    }
                }
            }
        }
        Ok(Self { fields })
    }
    /// Resolve only registered fields; parsing a key alone cannot publish a fact.
    pub fn definition(&self, key: FieldKey) -> Result<&FieldDefinition> {
        self.fields.get(&key).ok_or(Invalid::UnknownField)
    }
    /// Canonical field order for queries and condition compilation.
    pub fn fields(&self) -> impl Iterator<Item = &FieldDefinition> {
        self.fields.values()
    }
}

/// A declared path into a registered field. Array traversal has explicit set semantics.
pub struct FieldPath<'a> {
    /// Root definition owns source, sensitivity and version.
    pub root: &'a FieldDefinition,
    /// Leaf type after traversing declared arrays and properties.
    pub value_type: &'a ValueType,
    /// At least one array was traversed, so comparisons operate on a set of leaves.
    pub many: bool,
    segments: Vec<String>,
}
impl Catalog {
    /// Resolve only paths declared by a schema; arbitrary JSON paths are not accepted.
    pub fn path(&self, key: FieldKey) -> Result<FieldPath<'_>> {
        let (root, suffix) = if let Some(root) = self.fields.get(&key) {
            (root, "")
        } else {
            self.fields
                .values()
                .filter_map(|f| {
                    key.as_str()
                        .strip_prefix(f.key.as_str())
                        .and_then(|s| s.strip_prefix('.'))
                        .map(|s| (f, s))
                })
                .max_by_key(|(f, _)| f.key.as_str().len())
                .ok_or(Invalid::UnknownField)?
        };
        let segments: Vec<String> = if suffix.is_empty() {
            vec![]
        } else {
            suffix.split('.').map(str::to_owned).collect()
        };
        let mut value_type = &root.value_type;
        let mut many = false;
        for part in &segments {
            while let ValueType::Array { items, .. } = value_type {
                many = true;
                value_type = items;
            }
            let ValueType::Object { properties } = value_type else {
                return Err(Invalid::UnknownField);
            };
            value_type = properties.get(part).ok_or(Invalid::UnknownField)?;
        }
        while let ValueType::Array { items, .. } = value_type {
            many = true;
            value_type = items;
        }
        Ok(FieldPath {
            root,
            value_type,
            many,
            segments,
        })
    }
}
impl FieldPath<'_> {
    /// Read registered leaves; no unchecked coercion or missing-property fallback.
    pub fn values<'a>(&self, value: &'a Scalar) -> Result<Vec<&'a Scalar>> {
        fn collect<'a>(
            value: &'a Scalar,
            parts: &[String],
            out: &mut Vec<&'a Scalar>,
        ) -> Result<()> {
            if let Scalar::Array(values) = value {
                for value in values {
                    collect(value, parts, out)?;
                }
            } else if let Some((part, rest)) = parts.split_first() {
                let Scalar::Object(values) = value else {
                    return Err(Invalid::TypeMismatch);
                };
                collect(values.get(part).ok_or(Invalid::TypeMismatch)?, rest, out)?;
            } else {
                out.push(value);
            }
            Ok(())
        }
        self.root.validate_scalar(value)?;
        let mut result = Vec::new();
        collect(value, &self.segments, &mut result)?;
        Ok(result)
    }
}

impl ValueType {
    /// Decode provider JSON with the registered type; never infer a type from a field name.
    pub fn decode_json(&self, value: &serde_json::Value) -> Result<Scalar> {
        use serde_json::Value;
        let scalar = match (self, value) {
            (Self::String { .. } | Self::Enum { .. }, Value::String(s)) => {
                Scalar::String(s.clone())
            }
            (Self::Integer, Value::Number(n)) => {
                Scalar::Integer(n.as_i64().ok_or(Invalid::TypeMismatch)?)
            }
            (Self::Number, Value::Number(n)) => Scalar::Number(
                ordered_float::NotNan::new(n.as_f64().ok_or(Invalid::TypeMismatch)?)
                    .map_err(|_| Invalid::Value)?,
            ),
            (Self::Boolean, Value::Bool(b)) => Scalar::Boolean(*b),
            (Self::Time, Value::Number(n)) => {
                Scalar::Time(n.as_i64().ok_or(Invalid::TypeMismatch)?)
            }
            (Self::Array { items, max_items }, Value::Array(values))
                if values.len() <= *max_items as usize =>
            {
                Scalar::Array(
                    values
                        .iter()
                        .map(|v| items.decode_json(v))
                        .collect::<Result<_>>()?,
                )
            }
            (Self::Object { properties }, Value::Object(values))
                if properties.len() == values.len() =>
            {
                Scalar::Object(
                    properties
                        .iter()
                        .map(|(key, t)| {
                            Ok((
                                key.clone(),
                                t.decode_json(values.get(key).ok_or(Invalid::TypeMismatch)?)?,
                            ))
                        })
                        .collect::<Result<_>>()?,
                )
            }
            _ => return Err(Invalid::TypeMismatch),
        };
        self.validate_value(&scalar)?;
        Ok(scalar)
    }
}
