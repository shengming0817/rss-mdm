//! Bounded, explicit extraction and conversion shared by native and script collectors.
//! ref: serde-rs/json src/value/mod.rs@v1.0.145 (RFC 6901 selection).
use super::{
    FieldDefinition, FieldKey, NativeCardinality, NativeCollectionPlan, NativeType, Platform,
    Source, ValueType, WireError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Closed conversions; unknown native codes never become a successful default value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Conversion {
    /// Preserve the native JSON type, including explicit null.
    Identity,
    /// Convert a fully specified CIM datetime with explicit offset to UTC Unix seconds.
    CimTime,
    /// Parse an exact decimal integer string.
    Integer,
    /// Parse a finite JSON number or decimal number string.
    Number,
    /// Explicit source code to canonical scalar, including boolean values.
    Enum {
        /// Finite exact source tokens. Unknown tokens are invalid.
        #[schemars(schema_with = "crate::schema_values::enum_values")]
        values: BTreeMap<String, Value>,
    },
    /// Interpret membership in a complete integer array; never treat a numeric bitmask as a set.
    ArrayMember {
        /// Exact native enum member.
        member: i64,
        /// Value when present in the complete set.
        #[schemars(schema_with = "crate::schema_values::member_value")]
        present: Value,
        /// Value when absent from the complete set.
        #[schemars(schema_with = "crate::schema_values::member_value")]
        absent: Value,
    },
    /// Convert nonnegative integral units using checked exact rational arithmetic.
    Scale {
        /// Numerator.
        numerator: u64,
        /// Nonzero denominator; fractional output is rejected.
        denominator: u64,
    },
    /// Decode a finite nonnegative bitmask to a sorted list of declared flag names.
    Bitmask {
        /// Keys are decimal single-bit masks. Undeclared set bits are invalid.
        flags: BTreeMap<String, String>,
    },
}
/// Extraction relative to a response or list item. Empty pointer selects the whole value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValueMapping {
    /// RFC 6901 pointer, never an expression.
    pub pointer: String,
    /// Conversion of a direct scalar; structured projections require identity.
    pub conversion: Conversion,
    /// Exact output properties for each array item. No undeclared attributes are copied.
    pub columns: BTreeMap<String, ValueMapping>,
}
impl ValueMapping {
    /// Construct an explicit identity extraction.
    pub fn identity(pointer: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            conversion: Conversion::Identity,
            columns: BTreeMap::new(),
        }
    }
    /// Validate cumulative budgets and closed structural rules before publication.
    pub fn validate(&self) -> Result<(), WireError> {
        self.check(0, &mut 0)
    }
    fn check(&self, depth: usize, nodes: &mut usize) -> Result<(), WireError> {
        *nodes += 1;
        if depth > 4 || *nodes > 128 || !pointer(&self.pointer) || self.columns.len() > 64 {
            return Err(WireError::InvalidValue);
        }
        if !self.columns.is_empty() && self.conversion != Conversion::Identity {
            return Err(WireError::InvalidValue);
        }
        self.conversion.validate()?;
        for (name, mapping) in &self.columns {
            if name.is_empty()
                || name.len() > 64
                || !name.as_bytes()[0].is_ascii_lowercase()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(WireError::InvalidValue);
            }
            mapping.check(depth + 1, nodes)?;
        }
        Ok(())
    }
    /// Convert an already selected scalar or list row using its frozen destination type.
    /// Only an absent optional record member may be omitted; null and conversion failures
    /// remain explicit. The consumer validates converted values against the field schema.
    pub fn project_selected(&self, raw: &Value, ty: &ValueType) -> Result<Value, WireError> {
        self.validate_type(ty)?;
        fn project(m: &ValueMapping, raw: &Value, ty: &ValueType) -> Result<Value, WireError> {
            if m.columns.is_empty() {
                return m.conversion.apply(raw);
            }
            if !raw.is_object() {
                return Err(WireError::InvalidValue);
            }
            let mut result = serde_json::Map::new();
            for (name, column) in &m.columns {
                let (member, required) = match ty {
                    ValueType::Object { properties } => {
                        (properties.get(name).ok_or(WireError::InvalidValue)?, true)
                    }
                    ValueType::Record { properties } => {
                        let property = properties.get(name).ok_or(WireError::InvalidValue)?;
                        (&property.value_type, property.required)
                    }
                    _ => return Err(WireError::InvalidValue),
                };
                match raw.pointer(&column.pointer) {
                    Some(value) => {
                        result.insert(name.clone(), project(column, value, member)?);
                    }
                    None if !required => (),
                    None => return Err(WireError::InvalidValue),
                }
            }
            Ok(Value::Object(result))
        }
        project(self, raw, ty)
    }
}
impl Conversion {
    /// Check conversion declarations independently of any device value.
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::ArrayMember {member,present,absent} => {
                if *member < 0 || [present,absent].iter().any(|v| !matches!(v,Value::String(s) if !s.is_empty() && s.len()<=128 && !s.chars().any(char::is_control))) {return Err(WireError::InvalidValue);}
            }
            Self::Enum { values } => {
                if values.is_empty()
                    || values.len() > 128
                    || values.iter().any(|(k, v)| {
                        k.len() > 256
                            || k.chars().any(char::is_control)
                            || !matches!(v, Value::String(_) | Value::Bool(_) | Value::Number(_))
                            || v.as_str()
                                .is_some_and(|s| s.len() > 256 || s.contains('\0'))
                    })
                {
                    return Err(WireError::InvalidValue);
                }
            }
            Self::Scale {
                numerator,
                denominator,
            } if *numerator == 0 || *denominator == 0 => return Err(WireError::InvalidValue),
            Self::Bitmask { flags } => {
                let mut names = std::collections::BTreeSet::new();
                if flags.is_empty() || flags.len() > 63 {
                    return Err(WireError::InvalidValue);
                }
                for (bit, name) in flags {
                    let mask = bit.parse::<u64>().map_err(|_| WireError::InvalidValue)?;
                    if !mask.is_power_of_two()
                        || mask > i64::MAX as u64
                        || mask.to_string() != *bit
                        || name.is_empty()
                        || name.len() > 64
                        || name.chars().any(char::is_control)
                        || !names.insert(name)
                    {
                        return Err(WireError::InvalidValue);
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
    /// Apply the exact declared conversion. No truthiness, saturation or implicit rounding.
    pub fn apply(&self, raw: &Value) -> Result<Value, WireError> {
        self.validate()?;
        let integer = || match raw {
            Value::String(s) => s.parse::<i64>().map_err(|_| WireError::InvalidValue),
            v => v.as_i64().ok_or(WireError::InvalidValue),
        };
        match self {
            Self::ArrayMember {
                member,
                present,
                absent,
            } => {
                let items = raw.as_array().ok_or(WireError::InvalidValue)?;
                if items.len() > 65535 || items.iter().any(|v| v.as_i64().is_none()) {
                    return Err(WireError::InvalidValue);
                }
                Ok(if items.iter().any(|v| v.as_i64() == Some(*member)) {
                    present.clone()
                } else {
                    absent.clone()
                })
            }
            Self::Identity => Ok(raw.clone()),
            Self::CimTime => {
                let s = raw.as_str().ok_or(WireError::InvalidValue)?;
                if s.len() != 25
                    || !s.is_ascii()
                    || s.as_bytes()[14] != b'.'
                    || !matches!(s.as_bytes()[21], b'+' | b'-')
                    || !s[..14]
                        .bytes()
                        .chain(s[15..21].bytes())
                        .chain(s[22..].bytes())
                        .all(|b| b.is_ascii_digit())
                {
                    return Err(WireError::InvalidValue);
                }
                let n = |a: usize, b: usize| {
                    s[a..b].parse::<i32>().map_err(|_| WireError::InvalidValue)
                };
                let month =
                    time::Month::try_from(n(4, 6)? as u8).map_err(|_| WireError::InvalidValue)?;
                let date = time::Date::from_calendar_date(n(0, 4)?, month, n(6, 8)? as u8)
                    .map_err(|_| WireError::InvalidValue)?;
                let clock = time::Time::from_hms_micro(
                    n(8, 10)? as u8,
                    n(10, 12)? as u8,
                    n(12, 14)? as u8,
                    n(15, 21)? as u32,
                )
                .map_err(|_| WireError::InvalidValue)?;
                let seconds = n(22, 25)? * 60 * if s.as_bytes()[21] == b'-' { -1 } else { 1 };
                let offset = time::UtcOffset::from_whole_seconds(seconds)
                    .map_err(|_| WireError::InvalidValue)?;
                Ok(Value::from(
                    time::PrimitiveDateTime::new(date, clock)
                        .assume_offset(offset)
                        .unix_timestamp(),
                ))
            }
            Self::Integer => Ok(Value::from(integer()?)),
            Self::Number => {
                let n = match raw {
                    Value::String(s) => s.parse::<f64>().map_err(|_| WireError::InvalidValue)?,
                    v => v.as_f64().ok_or(WireError::InvalidValue)?,
                };
                serde_json::Number::from_f64(n)
                    .map(Value::Number)
                    .ok_or(WireError::InvalidValue)
            }
            Self::Enum { values } => {
                let key = match raw {
                    Value::String(s) => s.clone(),
                    Value::Number(_) | Value::Bool(_) => raw.to_string(),
                    _ => return Err(WireError::InvalidValue),
                };
                values.get(&key).cloned().ok_or(WireError::InvalidValue)
            }
            Self::Scale {
                numerator,
                denominator,
            } => {
                let input = match raw {
                    Value::String(s) => s.parse::<u64>().map_err(|_| WireError::InvalidValue)?,
                    v => v.as_u64().ok_or(WireError::InvalidValue)?,
                };
                let n = u128::from(input)
                    .checked_mul(u128::from(*numerator))
                    .ok_or(WireError::InvalidValue)?;
                let d = u128::from(*denominator);
                if n % d != 0 {
                    return Err(WireError::InvalidValue);
                }
                Ok(Value::from(
                    i64::try_from(n / d).map_err(|_| WireError::InvalidValue)?,
                ))
            }
            Self::Bitmask { flags } => {
                let n = u64::try_from(integer()?).map_err(|_| WireError::InvalidValue)?;
                let mut known = 0;
                let mut names = Vec::new();
                for (bit, name) in flags {
                    let bit: u64 = bit.parse().map_err(|_| WireError::InvalidValue)?;
                    known |= bit;
                    if n & bit != 0 {
                        names.push(name.clone());
                    }
                }
                if n & !known != 0 {
                    return Err(WireError::InvalidValue);
                }
                names.sort();
                Ok(serde_json::json!(names))
            }
        }
    }
}
pub(crate) fn pointer(value: &str) -> bool {
    if value.len() > 4096
        || (!value.is_empty() && !value.starts_with('/'))
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

/// Complete absence handling, never applied to failed or truncated queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeMissing {
    /// Preserve the prior fact and record Missing.
    Missing,
    /// Publish explicit null (only for nullable fields).
    Null,
    /// Publish a source-local tombstone.
    Delete,
}
/// One field binds to one reusable query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCollectionMapping {
    /// Explicit telemetry-only durable counter normalization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_normalization: Option<super::NativeCounterNormalization>,
    /// Stable query identity.
    pub query: String,
    /// Existing pointer and conversion semantics.
    pub mapping: ValueMapping,
    /// Explicit handling of complete absence.
    pub missing: NativeMissing,
}

fn validate_native_mapping(
    m: &ValueMapping,
    p: &BTreeMap<String, NativeType>,
    list: bool,
) -> Result<(), WireError> {
    if list || !m.columns.is_empty() {
        if !m.pointer.is_empty() || m.columns.is_empty() || m.conversion != Conversion::Identity {
            return Err(WireError::InvalidValue);
        }
        for column in m.columns.values() {
            validate_native_mapping(column, p, false)?;
        }
        return Ok(());
    }
    let key = m.pointer.strip_prefix('/').ok_or(WireError::InvalidValue)?;
    let ty = p.get(key).ok_or(WireError::InvalidValue)?;
    if !m.columns.is_empty() {
        return Err(WireError::InvalidValue);
    }
    use Conversion;
    if match &m.conversion {
        Conversion::Identity => false,
        Conversion::ArrayMember { .. } => {
            !matches!(ty, NativeType::Array {items} if **items==NativeType::Integer)
        }
        Conversion::CimTime => !matches!(ty, NativeType::CimTime),
        Conversion::Integer => !matches!(
            ty,
            NativeType::Integer | NativeType::UInt64 | NativeType::String
        ),
        Conversion::Number => !matches!(
            ty,
            NativeType::Number | NativeType::Integer | NativeType::String
        ),
        Conversion::Scale { .. } | Conversion::Bitmask { .. } => {
            !matches!(ty, NativeType::Integer | NativeType::UInt64)
        }
        Conversion::Enum { .. } => matches!(ty, NativeType::Array { .. }),
    } {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}

impl AgentCollectionMapping {
    /// Validate the source query and its statically known properties, without granting access.
    pub fn validate_query(&self, plan: &NativeCollectionPlan) -> Result<(), WireError> {
        self.mapping.validate()?;
        let query = plan
            .spec()
            .queries
            .get(&self.query)
            .ok_or(WireError::InvalidValue)?;
        validate_native_mapping(
            &self.mapping,
            &query.definition.properties(),
            query.cardinality == NativeCardinality::List,
        )
    }

    /// Bind a projection to an exact field and query. Counters are exclusive to telemetry.
    pub fn validate_field(
        &self,
        plan: &NativeCollectionPlan,
        field: &FieldDefinition,
        telemetry: bool,
    ) -> Result<(), WireError> {
        self.validate_query(plan)?;
        if (self.missing == NativeMissing::Null && !field.nullable)
            || (!telemetry && self.counter_normalization.is_some())
            || (telemetry && self.missing != NativeMissing::Missing)
        {
            return Err(WireError::InvalidValue);
        }
        let mut ty = field.value_type.clone();
        if telemetry {
            self.validate_counter_normalization(
                &plan.spec().queries[&self.query].definition,
                field,
            )?;
            if self.counter_normalization.is_some() {
                let start = &field
                    .time_series
                    .as_ref()
                    .ok_or(WireError::InvalidValue)?
                    .interval_start_path
                    .as_ref()
                    .ok_or(WireError::InvalidValue)?[0];
                let ValueType::Array { items, .. } = &mut ty else {
                    return Err(WireError::InvalidValue);
                };
                let ValueType::Object { properties } = items.as_mut() else {
                    return Err(WireError::InvalidValue);
                };
                properties.remove(start);
            }
        }
        self.mapping.validate_type(&ty)
    }
}
impl ValueMapping {
    /// Verify destination shape and conversion output types; raw identity values are checked at projection.
    pub fn validate_type(&self, ty: &ValueType) -> Result<(), WireError> {
        self.validate()?;
        ty.validate()?;
        fn check(m: &ValueMapping, ty: &ValueType) -> Result<(), WireError> {
            if !m.columns.is_empty() {
                match ty {
                    ValueType::Object { properties } => {
                        if m.columns.keys().ne(properties.keys()) {
                            return Err(WireError::InvalidValue);
                        }
                        for (name, column) in &m.columns {
                            check(column, &properties[name])?;
                        }
                    }
                    ValueType::Record { properties } => {
                        if properties
                            .iter()
                            .any(|(k, p)| p.required && !m.columns.contains_key(k))
                        {
                            return Err(WireError::InvalidValue);
                        }
                        for (name, column) in &m.columns {
                            check(
                                column,
                                &properties
                                    .get(name)
                                    .ok_or(WireError::InvalidValue)?
                                    .value_type,
                            )?;
                        }
                    }
                    _ => return Err(WireError::InvalidValue),
                }
                return Ok(());
            }
            let accepts = |v: &Value| -> bool {
                match ty {
                    ValueType::String {
                        max_length,
                        allow_empty,
                    } => v.as_str().is_some_and(|s| {
                        (*allow_empty || !s.is_empty()) && s.chars().count() <= *max_length as usize
                    }),
                    ValueType::Enum { values } => v.as_str().is_some_and(|s| values.contains(s)),
                    ValueType::Boolean => v.is_boolean(),
                    ValueType::Integer | ValueType::Time => v.as_i64().is_some(),
                    ValueType::Number => v.as_f64().is_some_and(f64::is_finite),
                    _ => false,
                }
            };
            let valid = match &m.conversion {
                Conversion::Identity => true,
                Conversion::CimTime => matches!(ty, ValueType::Time),
                Conversion::Integer | Conversion::Scale { .. } => {
                    matches!(ty, ValueType::Integer | ValueType::Time)
                }
                Conversion::Number => matches!(ty, ValueType::Number),
                Conversion::Enum { values } => values.values().all(accepts),
                Conversion::ArrayMember {
                    present, absent, ..
                } => accepts(present) && accepts(absent),
                Conversion::Bitmask { flags } => match ty {
                    ValueType::Array { items, max_items } if flags.len() <= *max_items as usize => {
                        match items.as_ref() {
                            ValueType::String { max_length, .. } => flags
                                .values()
                                .all(|s| s.chars().count() <= *max_length as usize),
                            ValueType::Enum { values } => {
                                flags.values().all(|s| values.contains(s))
                            }
                            _ => false,
                        }
                    }
                    _ => false,
                },
            };
            if valid {
                Ok(())
            } else {
                Err(WireError::InvalidValue)
            }
        }
        let ty = match ty {
            ValueType::Array { items, .. }
                if !matches!(self.conversion, Conversion::Bitmask { .. }) =>
            {
                items.as_ref()
            }
            ty => ty,
        };
        check(self, ty)
    }
}

/// Validate a frozen field set independently of catalog/source authorization.
pub fn validate_projection_fields(
    fields: &[FieldDefinition],
    source: Source,
    platform: Platform,
) -> Result<(), WireError> {
    if fields.is_empty() || fields.len() > 64 {
        return Err(WireError::InvalidValue);
    }
    let mut keys = std::collections::BTreeSet::new();
    for field in fields {
        field.validate()?;
        if !keys.insert(field.key)
            || !field.sources.contains_key(&source)
            || !field.platforms.contains(&platform)
        {
            return Err(WireError::InvalidValue);
        }
    }
    Ok(())
}
/// Validate an exact native mapping set. This does not authenticate a task or grant local read access.
pub fn validate_native_projection(
    fields: &[FieldDefinition],
    mappings: &BTreeMap<String, AgentCollectionMapping>,
    plan: &NativeCollectionPlan,
    telemetry: bool,
) -> Result<(), WireError> {
    let platform = match plan.platform() {
        super::TaskPlatform::Windows => Platform::Windows,
        super::TaskPlatform::Macos => Platform::Macos,
    };
    validate_projection_fields(fields, Source::AgentNative, platform)?;
    validate_projection_size(&(fields, mappings))?;
    if fields.len() != mappings.len() {
        return Err(WireError::InvalidValue);
    }
    for field in fields {
        mappings
            .get(field.key.as_str())
            .ok_or(WireError::InvalidValue)?
            .validate_field(plan, field, telemetry)?;
    }
    Ok(())
}
/// Validate script projections against the exact configured field subset.
pub fn validate_script_projection(
    fields: &[FieldDefinition],
    mappings: &BTreeMap<String, ValueMapping>,
) -> Result<(), WireError> {
    validate_projection_size(&(fields, mappings))?;
    if fields.len() != mappings.len() {
        return Err(WireError::InvalidValue);
    }
    for field in fields {
        FieldKey::parse(field.key.as_str())?;
        mappings
            .get(field.key.as_str())
            .ok_or(WireError::InvalidValue)?
            .validate_type(&field.value_type)?;
    }
    Ok(())
}
/// Explicit script purpose. Absence is not an older non-collection task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ScriptProjection {
    /// No collection facts are produced by this task.
    None,
    /// Exact frozen collection output; neither a local query grant nor final Inventory facts.
    Collection {
        /// Current field definitions frozen by the producer.
        fields: Vec<FieldDefinition>,
        /// Exact mappings of the output document.
        mappings: BTreeMap<String, ValueMapping>,
        /// Published output shape, interpreted by the existing script consumer.
        #[schemars(schema_with = "crate::schema_values::object_schema_document")]
        output_schema: Value,
        /// Original collection range; it grants no additional execution scope.
        scope: crate::CollectionScope,
    },
}
impl ScriptProjection {
    /// Validate a frozen script projection for its signed source and platform.
    pub fn validate(
        &self,
        profile: super::ExecutorProfile,
        platform: super::TaskPlatform,
    ) -> Result<(), WireError> {
        validate_projection_size(self)?;
        if let Self::Collection {
            fields,
            mappings,
            output_schema,
            scope,
        } = self
        {
            scope.validate_executable()?;
            if !output_schema.is_object()
                || serde_json::to_vec(output_schema)
                    .map_err(|_| WireError::InvalidValue)?
                    .len()
                    > 65536
            {
                return Err(WireError::InvalidValue);
            }
            let source = if profile == super::ExecutorProfile::Osquery {
                Source::AgentOsquery
            } else {
                Source::AgentScript
            };
            let platform = match platform {
                super::TaskPlatform::Windows => Platform::Windows,
                super::TaskPlatform::Macos => Platform::Macos,
            };
            validate_projection_fields(fields, source, platform)?;
            validate_script_projection(fields, mappings)?;
        }
        Ok(())
    }
}

/// Bound a complete frozen projection, leaving room for the existing plan and signed envelope.
/// The complete signed message remains subject to its own existing byte limit.
pub fn validate_projection_size(value: &impl Serialize) -> Result<(), WireError> {
    if serde_json::to_vec(value)
        .map_err(|_| WireError::InvalidValue)?
        .len()
        > 49_152
    {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}
