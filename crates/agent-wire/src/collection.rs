//! Protocol-owned collection definitions and values. No Inventory or Observation authority.
use super::WireError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, WireError>;
fn bounded_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(WireError::InvalidValue)
    } else {
        Ok(())
    }
}
/// All allowed asset sources. Serialized as their canonical stable identifier.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum Source {
    /// Controlled collection script evidence.
    #[serde(rename = "agent.script")]
    AgentScript,
    /// Signed declarative native task evidence.
    #[serde(rename = "agent.native")]
    AgentNative,
    /// Published SQL template evidence.
    #[serde(rename = "agent.osquery")]
    AgentOsquery,
    /// Apple MDM evidence.
    #[serde(rename = "mdm.apple")]
    MdmApple,
    /// Built-in agent evidence.
    #[serde(rename = "agent.builtin")]
    AgentBuiltin,
    /// Administrator assignment.
    #[serde(rename = "manual")]
    Manual,
    /// Windows MDM evidence.
    #[serde(rename = "mdm.windows")]
    MdmWindows,
}
/// Bounded protocol field identity; parsing grants no catalog or source authority.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, schemars::JsonSchema)]
#[schemars(with = "String", extend("maxLength" = 128, "pattern" = r"^(device|custom|channel)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"))]
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
    /// Validate a bounded, namespaced ASCII key without consulting a catalog.
    pub fn parse(value: &str) -> Result<Self> {
        let mut parts = value.split('.');
        if value.len() > 128 || !matches!(parts.next(), Some("device" | "custom" | "channel")) {
            return Err(WireError::InvalidValue);
        }
        let mut count = 0;
        for part in parts {
            if part.is_empty()
                || !part.as_bytes()[0].is_ascii_lowercase()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(WireError::InvalidValue);
            }
            count += 1;
        }
        if count == 0 {
            return Err(WireError::InvalidValue);
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
        #[schemars(extend("minimum" = 1, "maximum" = 65536))]
        max_length: u32,
        /// Whether empty text is allowed.
        allow_empty: bool,
    },
    /// Closed string vocabulary.
    Enum {
        /// Permitted nonempty values.
        #[schemars(extend("minItems" = 1, "maxItems" = 128, "uniqueItems" = true, "items" = serde_json::json!({"type":"string","minLength":1,"maxLength":256})))]
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
        #[schemars(extend("minimum" = 1, "maximum" = 100000))]
        max_items: u32,
    },
    /// Closed properties; undeclared and absent properties are rejected.
    Object {
        /// Property schema by literal name.
        #[schemars(extend("minProperties" = 1, "maxProperties" = 64, "propertyNames" = serde_json::json!({"type":"string","maxLength":64,"pattern":"^[a-z][a-z0-9_]*$"})))]
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
            return Err(WireError::InvalidValue);
        }
        match self {
            Self::String { max_length, .. } if !(1..=65536).contains(max_length) => {
                Err(WireError::InvalidValue)
            }
            Self::Enum { values } => {
                if values.is_empty()
                    || values.len() > 128
                    || values
                        .iter()
                        .any(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
                {
                    Err(WireError::InvalidValue)
                } else {
                    Ok(())
                }
            }
            Self::Array { items, max_items } => {
                if !(1..=100000).contains(max_items) {
                    return Err(WireError::InvalidValue);
                }
                items.check(depth + 1, nodes)
            }
            Self::Object { properties } => {
                if properties.is_empty() || properties.len() > 64 {
                    return Err(WireError::InvalidValue);
                }
                for (key, value) in properties {
                    if !property(key) {
                        return Err(WireError::InvalidValue);
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
                    t.validate_value(values.get(k).ok_or(WireError::InvalidValue)?)
                })
            }
            _ => Err(WireError::InvalidValue),
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
/// Platform applicable to a field or collector.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Windows.
    Windows,
    /// macOS.
    Macos,
}
/// Field visibility class, enforced by the product authorization boundary.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Ordinary inventory.
    Standard,
    /// Requires the sensitive inventory permission.
    Sensitive,
}
/// A published field version. No time-based expiry and no execution permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldDefinition {
    /// Stable field identity.
    #[schemars(extend("maxLength" = 128, "pattern" = "^(device|custom|channel)\\.[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)*$"))]
    pub key: FieldKey,
    /// Monotonic published version.
    #[schemars(extend("minimum" = 1, "maximum" = 9223372036854775807u64))]
    pub version: u64,
    /// Exact bounded type.
    pub value_type: ValueType,
    /// Accept explicit null as distinct from deletion.
    pub nullable: bool,
    /// Whether management assignment is permitted.
    pub manual: bool,
    /// Allowed sources with priority; lower numbers win, equal numbers require consensus.
    #[schemars(schema_with = "source_priorities_schema", extend("minProperties" = 1))]
    pub sources: BTreeMap<Source, u16>,
    /// Supported platforms.
    #[schemars(extend("minItems" = 1, "maxItems" = 2))]
    pub platforms: BTreeSet<Platform>,
    /// Read/filter visibility classification.
    pub sensitivity: Sensitivity,
    /// Exact optional unit; no implicit conversion.
    #[schemars(
        required,
        schema_with = "crate::self_service::nullable_schema::<String>"
    )]
    #[schemars(extend("minLength" = 1, "maxLength" = 64))]
    pub unit: Option<String>,
    /// Whether this field participates in conditions/search.
    pub searchable: bool,
    /// Optional stable item-key property for a structured inventory list.
    #[schemars(
        required,
        schema_with = "crate::self_service::nullable_schema::<String>"
    )]
    #[schemars(extend("maxLength" = 64, "pattern" = "^[a-z][a-z0-9_]*$"))]
    pub item_key: Option<String>,
}
fn source_priorities_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut schema = <BTreeMap<Source, u16> as schemars::JsonSchema>::json_schema(generator);
    schema.insert(
        "propertyNames".into(),
        generator.subschema_for::<Source>().to_value(),
    );
    schema
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
            return Err(WireError::InvalidValue);
        }
        if let Some(key) = &self.item_key {
            let ValueType::Array { items, .. } = &self.value_type else {
                return Err(WireError::InvalidValue);
            };
            let ValueType::Object { properties } = items.as_ref() else {
                return Err(WireError::InvalidValue);
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
                return Err(WireError::InvalidValue);
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
                    return Err(WireError::InvalidValue);
                };
                if !identities.insert(properties.get(key).ok_or(WireError::InvalidValue)?) {
                    return Err(WireError::InvalidValue);
                }
            }
        }
        Ok(())
    }
}
/// Explicitly typed asset scalar. Times are UTC Unix seconds, never validity windows.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Scalar {
    /// Nonblank bounded text.
    String(#[schemars(extend("maxLength" = 65536))] String),
    /// Signed integer.
    Integer(
        #[schemars(extend("minimum" = -9223372036854775808i64, "maximum" = 9223372036854775807u64))]
         i64,
    ),
    /// Finite numeric observation.
    Number(#[schemars(with = "f64")] ordered_float::NotNan<f64>),
    /// Ordered bounded collection.
    Array(#[schemars(extend("maxItems" = 100000))] Vec<Scalar>),
    /// Declared structured attributes.
    Object(
        #[schemars(extend("maxProperties" = 64, "propertyNames" = serde_json::json!({"type":"string","maxLength":64,"pattern":"^[a-z][a-z0-9_]*$"})))]
         BTreeMap<String, Scalar>,
    ),
    /// Boolean value, including false.
    Boolean(bool),
    /// UTC Unix seconds.
    Time(i64),
}
impl Scalar {
    /// Declared scalar kind.
    pub fn kind(&self) -> Kind {
        match self {
            Self::String(_) => Kind::String,
            Self::Integer(_) => Kind::Integer,
            Self::Number(_) => Kind::Number,
            Self::Array(_) => Kind::Array,
            Self::Object(_) => Kind::Object,
            Self::Boolean(_) => Kind::Boolean,
            Self::Time(_) => Kind::Time,
        }
    }
    /// Validate bounded text and the canonical time range.
    pub fn validate(&self) -> Result<()> {
        fn visit(value: &Scalar, depth: usize, nodes: &mut usize, bytes: &mut usize) -> Result<()> {
            *nodes += 1;
            if depth > 5 || *nodes > 200000 {
                return Err(WireError::InvalidValue);
            }
            match value {
                Scalar::String(s) => {
                    *bytes = bytes.checked_add(s.len()).ok_or(WireError::InvalidValue)?;
                    if s.chars().any(|c| c == '\0') || *bytes > 16 * 1024 * 1024 {
                        return Err(WireError::InvalidValue);
                    }
                }
                Scalar::Number(n) if !n.into_inner().is_finite() => {
                    return Err(WireError::InvalidValue);
                }
                Scalar::Time(t) if *t < 0 => {
                    return Err(WireError::InvalidValue);
                }
                Scalar::Array(values) => {
                    for v in values {
                        visit(v, depth + 1, nodes, bytes)?
                    }
                }
                Scalar::Object(values) => {
                    for (key, v) in values {
                        *bytes += key.len();
                        visit(v, depth + 1, nodes, bytes)?
                    }
                }
                _ => (),
            }
            Ok(())
        }
        visit(self, 0, &mut 0, &mut 0)
    }
}
/// Definitive per-field outcome. Failed/missing attempts never delete a last-known fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CollectedValue {
    /// Typed value validated against the frozen field version.
    Value(Scalar),
    /// Explicit legal null.
    Null,
    /// Explicit removal of this source's field; never inferred from failure.
    Deleted,
    /// Collector explicitly cannot provide this field.
    Unsupported,
}
impl CollectedValue {
    /// Encode only the current schema after checking its frozen field definition.
    pub fn encode(&self, definition: &FieldDefinition) -> Result<Vec<u8>> {
        self.validate(definition)?;
        serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)
    }
    /// Check the value against the field carried by this message, without product admission.
    pub fn validate(&self, definition: &FieldDefinition) -> Result<()> {
        match self {
            Self::Value(v) => definition.validate_scalar(v),
            Self::Null if !definition.nullable => Err(WireError::InvalidValue),
            _ => Ok(()),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Definition {
    #[schemars(extend("minLength" = 1, "maxLength" = 128, "pattern" = "^[^\\u0000-\\u001F\\u007F]+$"))]
    dataset: String,
    #[schemars(extend("minLength" = 1, "maxLength" = 128, "pattern" = "^[^\\u0000-\\u001F\\u007F]+$"))]
    version: String,
    #[schemars(extend("not" = serde_json::json!({"const":"manual"})))]
    source: Source,
    #[schemars(extend("const" = serde_json::json!({"kind":"device"})))]
    scope: crate::CollectionScope,
    #[schemars(extend("minItems" = 1, "maxItems" = 128))]
    fields: Vec<FieldDefinition>,
}
/// Frozen source and field definitions for one published collector version.
/// Constructing this value validates structure; the caller still owns tenant/device authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "Definition", into = "Definition")]
pub struct CollectionDefinition(Definition);
impl TryFrom<Definition> for CollectionDefinition {
    type Error = WireError;
    fn try_from(value: Definition) -> Result<Self> {
        value.scope.validate_executable()?;
        Self::new(&value.dataset, &value.version, value.source, value.fields)
    }
}
impl From<CollectionDefinition> for Definition {
    fn from(value: CollectionDefinition) -> Self {
        value.0
    }
}
impl CollectionDefinition {
    /// Bind a finite unique field set to one device source and immutable definition version.
    pub fn new(
        dataset: &str,
        version: impl ToString,
        source: Source,
        mut fields: Vec<FieldDefinition>,
    ) -> Result<Self> {
        bounded_id(dataset)?;
        let version = version.to_string();
        bounded_id(&version)?;
        if dataset.len() > 128
            || version.len() > 128
            || source == Source::Manual
            || fields.is_empty()
            || fields.len() > 128
        {
            return Err(WireError::InvalidValue);
        }
        let mut keys = BTreeSet::new();
        for field in &fields {
            field.validate()?;
            if !keys.insert(field.key) {
                return Err(WireError::InvalidValue);
            }
        }
        for key in &keys {
            for (index, _) in key.as_str().match_indices('.') {
                if FieldKey::parse(&key.as_str()[..index])
                    .is_ok_and(|parent| keys.contains(&parent))
                {
                    return Err(WireError::InvalidValue);
                }
            }
        }
        if fields.iter().any(|f| !f.sources.contains_key(&source)) {
            return Err(WireError::InvalidValue);
        }
        fields.sort_by_key(|f| f.key);
        Ok(Self(Definition {
            dataset: dataset.into(),
            version,
            source,
            scope: crate::CollectionScope::Device,
            fields,
        }))
    }
    /// Dataset selected by the product stream owner.
    pub fn dataset(&self) -> &str {
        &self.0.dataset
    }
    /// Exact source; never inferred from user-supplied field names.
    pub fn source(&self) -> Source {
        self.0.source
    }
    /// Immutable definition number.
    pub fn version(&self) -> &str {
        &self.0.version
    }
    /// Canonical unique field order, also used for completeness reporting.
    pub fn fields(&self) -> &[FieldDefinition] {
        &self.0.fields
    }
    /// Resolve a field only within this frozen coverage.
    pub fn field(&self, key: FieldKey) -> Result<&FieldDefinition> {
        self.0
            .fields
            .iter()
            .find(|f| f.key == key)
            .ok_or(WireError::InvalidValue)
    }
    /// Exact content identity includes schemas, sources and all definition constraints.
    pub fn fingerprint(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&self.0).map_err(|_| WireError::InvalidValue)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}
