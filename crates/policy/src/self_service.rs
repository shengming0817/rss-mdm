//! Script parameter sources and self-service configuration, shared by every caller.
use crate::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Where one Resource-declared argument obtains its value.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParameterSource {
    /// Administrator-selected literal; callers cannot override it.
    Fixed {
        /// Value checked against the Resource's parameter schema.
        #[schemars(schema_with = "scalar_schema")]
        value: Value,
    },
    /// Required call-time argument, governed by the same Resource schema.
    Input {},
}
/// Complete parameter-source map; Resource owns all value constraints.
#[derive(Clone, Debug, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct ParameterSources(pub BTreeMap<String, ParameterSource>);
impl ParameterSources {
    /// Whether this definition needs call-time input.
    pub fn has_input(&self) -> bool {
        self.0
            .values()
            .any(|p| matches!(p, ParameterSource::Input { .. }))
    }
    /// Check bounded literal shape, without duplicating Resource constraints.
    pub fn validate(&self) -> Result<(), Error> {
        if self.0.len() > 32
            || serde_json::to_vec(self)
                .map_err(|_| Error::Malformed)?
                .len()
                > 65536
        {
            return Err(Error::Malformed);
        }
        for (name, source) in &self.0 {
            if name.is_empty()
                || name.len() > 64
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(Error::Malformed);
            }
            if let ParameterSource::Fixed { value } = source {
                if !(value.is_string() || value.is_boolean() || value.as_i64().is_some())
                    || value.as_str().is_some_and(|s| s.contains('\0'))
                {
                    return Err(Error::Malformed);
                }
            }
        }
        Ok(())
    }
    /// Resolve exactly the declared call inputs; no coercion or implicit defaults.
    pub fn resolve(&self, input: &Value) -> Result<Value, Error> {
        self.validate()?;
        let input = input.as_object().ok_or(Error::Malformed)?;
        if input.len()
            != self
                .0
                .values()
                .filter(|p| matches!(p, ParameterSource::Input { .. }))
                .count()
        {
            return Err(Error::Malformed);
        }
        let mut values = Map::new();
        for (name, source) in &self.0 {
            let value = match source {
                ParameterSource::Fixed { value } => value.clone(),
                ParameterSource::Input { .. } => input.get(name).ok_or(Error::Malformed)?.clone(),
            };
            values.insert(name.clone(), value);
        }
        if input
            .keys()
            .any(|name| !matches!(self.0.get(name), Some(ParameterSource::Input { .. })))
        {
            return Err(Error::Malformed);
        }
        Ok(Value::Object(values))
    }
    /// Fixed values for Resource-owned partial validation at publication.
    pub fn fixed_values(&self) -> Value {
        Value::Object(
            self.0
                .iter()
                .filter_map(|(name, p)| match p {
                    ParameterSource::Fixed { value } => Some((name.clone(), value.clone())),
                    ParameterSource::Input { .. } => None,
                })
                .collect(),
        )
    }
}
/// Closed self-service script AI risk. No unknown or implicit client fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct ScriptRisk(u8);
impl ScriptRisk {
    /// Execute within the existing rules without a confirmation prompt.
    pub const DIRECT: Self = Self(1);
    /// AI invocation requires the caller's local confirmation.
    pub const CONFIRM: Self = Self(2);
    /// Numeric canonical representation.
    pub fn value(self) -> u8 {
        self.0
    }
}
impl TryFrom<u8> for ScriptRisk {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        if matches!(value, 1 | 2) {
            Ok(Self(value))
        } else {
            Err(Error::Malformed)
        }
    }
}
impl From<ScriptRisk> for u8 {
    fn from(value: ScriptRisk) -> Self {
        value.0
    }
}
/// Policy-owned self-service configuration. Missing input defaults are normalized by CAS.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfService {
    /// Whether new self-service calls are accepted.
    pub published: bool,
    /// Display name in the authorized directory.
    pub display_name: String,
    /// Intended purpose.
    pub description: String,
    /// Preconditions shown before invocation.
    pub prerequisites: String,
    /// Expected side effects shown before invocation.
    pub side_effects: String,
    /// Presentation category, independent of Scope.
    pub category: String,
    /// Bounded search terms.
    pub keywords: Vec<String>,
    /// Defaults only at first configuration; normalized stored values are always present.
    #[serde(default)]
    pub allow_ai: Option<bool>,
    /// Defaults to confirmation at first configuration; only levels one and two are legal.
    #[serde(default)]
    pub risk_level: Option<ScriptRisk>,
}
impl SelfService {
    /// Fill absent input fields from the previous configuration or first-use defaults.
    pub fn normalize(&mut self, old: Option<&Self>) {
        self.allow_ai = Some(
            self.allow_ai
                .or_else(|| old.and_then(|c| c.allow_ai))
                .unwrap_or(true),
        );
        self.risk_level = Some(
            self.risk_level
                .or_else(|| old.and_then(|c| c.risk_level))
                .unwrap_or(ScriptRisk::CONFIRM),
        );
    }
    /// Validate metadata bounds. Publication does not confer execution authority.
    pub fn validate(&self) -> Result<(), Error> {
        if self.display_name.trim().is_empty()
            || self.category.trim().is_empty()
            || self.keywords.len() > 32
        {
            return Err(Error::Malformed);
        }
        for (s, bound) in [
            (&self.display_name, 256),
            (&self.description, 4096),
            (&self.prerequisites, 4096),
            (&self.side_effects, 4096),
            (&self.category, 128),
        ] {
            if s.len() > bound || s.contains('\0') {
                return Err(Error::Malformed);
            }
        }
        if self
            .keywords
            .iter()
            .any(|s| s.trim().is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

impl schemars::JsonSchema for ScriptRisk {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ScriptRisk".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type":"integer","enum":[1,2]})
    }
}
fn scalar_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"anyOf":[{"type":"string","pattern":"^[^\\u0000]*$"},{"type":"boolean"},{"type":"integer","minimum":-9223372036854775808i64,"maximum":9223372036854775807i64}]})
}
