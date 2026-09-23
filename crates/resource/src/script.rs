//! Frozen execution interface. Values are arguments, never shell command fragments.
use crate::{Error, Platform};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Supported executor profiles; osquery uses a fixed product-owned query.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptProfile {
    /// PowerShell 7 on Windows.
    PowerShell7,
    /// POSIX sh on macOS.
    PosixSh,
    /// Bash on macOS.
    Bash,
    /// The fixed `SELECT version FROM osquery_info;` collection.
    OsqueryInfoV1,
}
/// Explicit execution identity; no implicit elevation or fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunAs {
    /// Machine service identity.
    System,
    /// An available interactive user; otherwise execution fails.
    LoggedInUser,
}
/// Content and output encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptEncoding {
    /// Strict UTF-8, with invalid bytes rejected.
    Utf8,
}
/// An argument destination; values must never be interpolated into source text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParameterBinding {
    /// A literal PowerShell parameter name.
    Named {
        /// ASCII identifier without a prefix or expression.
        name: String,
    },
    /// A shell positional argument.
    Positional {
        /// Zero-based position, contiguous across the definition.
        index: u16,
    },
    /// A product-prefixed environment variable, separate from the inherited environment.
    Environment {
        /// Must begin with `RSS_PARAM_` to exclude interpreter startup variables.
        name: String,
    },
}
/// Collection fields owned by the product's finite inventory catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ScriptField {
    /// Corporate agent version as text.
    #[serde(rename = "custom.corporate_agent.version")]
    CorporateAgentVersion,
    /// Corporate agent health as a boolean.
    #[serde(rename = "custom.corporate_agent.healthy")]
    CorporateAgentHealthy,
    /// Version reported by the fixed osquery profile.
    #[serde(rename = "custom.osquery.version")]
    OsqueryVersion,
}
/// Declared purpose is part of the immutable digest, not inferred from script text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScriptPurpose {
    /// An operation whose exit status alone does not prove a device state.
    Action,
    /// A typed, explicitly mapped collection output.
    Collection {
        /// JSON pointers into the validated output, keyed by the finite field catalog.
        mappings: BTreeMap<ScriptField, String>,
    },
}
/// Complete execution interface. Use [`ScriptDefinition::new`] to validate and freeze it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptSpec {
    /// Selected executor profile.
    pub profile: ScriptProfile,
    /// Required execution identity.
    pub run_as: RunAs,
    /// Exact artifact/output encoding.
    pub encoding: ScriptEncoding,
    /// Self-contained JSON Schema draft 2020-12 for the argument object.
    pub parameters: Value,
    /// Exactly one destination for every declared parameter.
    pub bindings: BTreeMap<String, ParameterBinding>,
    /// Self-contained JSON Schema draft 2020-12 for successful output.
    pub output: Value,
    /// Purpose and optional collection field mapping.
    pub purpose: ScriptPurpose,
    /// Execution wall-time limit, from 1 to 3600 seconds.
    pub timeout_seconds: u32,
    /// Combined output budget, from 1 to 1 MiB.
    pub output_bytes: u32,
    /// Output row limit, from 1 to 1000.
    pub max_rows: u16,
}
/// Validated immutable execution interface; deserialization uses the same constructor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ScriptSpec", into = "ScriptSpec")]
pub struct ScriptDefinition(ScriptSpec);
impl From<ScriptDefinition> for ScriptSpec {
    fn from(value: ScriptDefinition) -> Self {
        value.0
    }
}
impl TryFrom<ScriptSpec> for ScriptDefinition {
    type Error = Error;
    fn try_from(value: ScriptSpec) -> Result<Self, Error> {
        Self::new(value)
    }
}
impl ScriptDefinition {
    /// Validate schemas, budgets, argument destinations and collection mappings.
    pub fn new(spec: ScriptSpec) -> Result<Self, Error> {
        if !(1..=3600).contains(&spec.timeout_seconds)
            || !(1..=1_048_576).contains(&spec.output_bytes)
            || !(1..=1000).contains(&spec.max_rows)
        {
            return Err(Error::InvalidInput);
        }
        schema(&spec.parameters)?;
        schema(&spec.output)?;
        bindings(&spec)?;
        purpose(&spec)?;
        Ok(Self(spec))
    }
    /// Borrow the frozen execution interface.
    pub fn spec(&self) -> &ScriptSpec {
        &self.0
    }
    /// Validate exact platform/profile pairing without probing a device.
    pub fn validate_platform(&self, platform: Platform) -> Result<(), Error> {
        match (self.0.profile, platform) {
            (ScriptProfile::PowerShell7, Platform::Windows)
            | (ScriptProfile::PosixSh | ScriptProfile::Bash, Platform::MacOS)
            | (ScriptProfile::OsqueryInfoV1, _) => Ok(()),
            _ => Err(Error::InvalidInput),
        }
    }
    /// Validate bounded literal arguments against the frozen input schema.
    pub fn validate_parameters(&self, value: &Value) -> Result<(), Error> {
        validate(&self.0.parameters, value, 65_536)?;
        if value.as_object().is_none_or(|object| {
            object.values().any(|v| {
                !(v.is_string() || v.is_boolean() || v.as_i64().is_some())
                    || v.as_str().is_some_and(|s| s.contains('\0'))
            })
        }) {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// Validate successful, complete output. Execution quality is checked by the caller.
    pub fn validate_output(&self, value: &Value) -> Result<(), Error> {
        output_structure(value, self.0.max_rows as usize, 0)?;
        validate(&self.0.output, value, self.0.output_bytes as usize)?;
        if value
            .as_array()
            .is_some_and(|rows| rows.len() > self.0.max_rows as usize)
        {
            return Err(Error::InvalidInput);
        }
        if let ScriptPurpose::Collection { mappings } = &self.0.purpose {
            for (field, pointer) in mappings {
                let value = value.pointer(pointer).ok_or(Error::InvalidInput)?;
                let valid = match field {
                    ScriptField::CorporateAgentHealthy => value.is_boolean(),
                    _ => value.as_str().is_some_and(|s| {
                        !s.trim().is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
                    }),
                };
                if !valid {
                    return Err(Error::InvalidInput);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn canonical(&self) -> Vec<u8> {
        // All keys are sorted by serde_json's default Map and BTreeMap. No floats
        // are accepted as argument values; schema number serialization is stable.
        serde_json::to_vec(&self.0).expect("validated JSON-only script definition")
    }
}
fn validate(schema: &Value, value: &Value, limit: usize) -> Result<(), Error> {
    if serde_json::to_vec(value)
        .map_err(|_| Error::InvalidInput)?
        .len()
        > limit
    {
        return Err(Error::InvalidInput);
    }
    let validator = jsonschema::draft202012::new(schema).map_err(|_| Error::InvalidInput)?;
    if validator.is_valid(value) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}
fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn bindings(spec: &ScriptSpec) -> Result<(), Error> {
    let params = spec.parameters.as_object().ok_or(Error::InvalidInput)?;
    let props = params
        .get("properties")
        .and_then(Value::as_object)
        .ok_or(Error::InvalidInput)?;
    let required = params
        .get("required")
        .and_then(Value::as_array)
        .ok_or(Error::InvalidInput)?;
    if params.get("type") != Some(&Value::from("object"))
        || params.get("additionalProperties") != Some(&Value::Bool(false))
        || props.len() > 32
        || props.len() != spec.bindings.len()
        || required.len() != props.len()
        || required
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>()
            != props.keys().map(String::as_str).collect()
    {
        return Err(Error::InvalidInput);
    }
    let mut destinations = BTreeSet::new();
    let mut positions = BTreeSet::new();
    for (key, binding) in &spec.bindings {
        if !identifier(key) || !props.contains_key(key) {
            return Err(Error::InvalidInput);
        }
        let destination = match binding {
            ParameterBinding::Named { name }
                if spec.profile == ScriptProfile::PowerShell7 && identifier(name) =>
            {
                format!("named:{}", name.to_ascii_lowercase())
            }
            ParameterBinding::Positional { index }
                if matches!(spec.profile, ScriptProfile::PosixSh | ScriptProfile::Bash) =>
            {
                positions.insert(*index);
                format!("position:{index}")
            }
            ParameterBinding::Environment { name }
                if name.starts_with("RSS_PARAM_") && name.len() > 10 && identifier(name) =>
            {
                format!("env:{}", name.to_ascii_uppercase())
            }
            _ => return Err(Error::InvalidInput),
        };
        if !destinations.insert(destination) {
            return Err(Error::InvalidInput);
        }
    }
    if positions.iter().copied().ne(0..positions.len() as u16) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn purpose(spec: &ScriptSpec) -> Result<(), Error> {
    if let ScriptPurpose::Collection { mappings } = &spec.purpose
        && (mappings.is_empty() || mappings.values().any(|p| !pointer(p)))
    {
        return Err(Error::InvalidInput);
    }
    if spec.profile == ScriptProfile::OsqueryInfoV1 {
        let ScriptPurpose::Collection { mappings } = &spec.purpose else {
            return Err(Error::InvalidInput);
        };
        if !spec.bindings.is_empty()
            || spec.run_as != RunAs::System
            || spec.max_rows != 1
            || mappings.len() != 1
            || mappings
                .get(&ScriptField::OsqueryVersion)
                .map(String::as_str)
                != Some("/0/version")
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}
fn pointer(value: &str) -> bool {
    if !value.starts_with('/') || value.len() > 256 || value.chars().any(char::is_control) {
        return false;
    }
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        if b == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}
fn schema(value: &Value) -> Result<(), Error> {
    if serde_json::to_vec(value)
        .map_err(|_| Error::InvalidInput)?
        .len()
        > 16_384
    {
        return Err(Error::InvalidInput);
    }
    let mut nodes = 0;
    bounded_schema(value, 0, &mut nodes)?;
    jsonschema::draft202012::new(value).map_err(|_| Error::InvalidInput)?;
    Ok(())
}
fn bounded_schema(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), Error> {
    *nodes += 1;
    if depth > 16 || *nodes > 1024 {
        return Err(Error::InvalidInput);
    }
    let object = value.as_object().ok_or(Error::InvalidInput)?;
    for (key, value) in object {
        match key.as_str() {
            "type" => {
                if !matches!(
                    value.as_str(),
                    Some("object" | "array" | "string" | "integer" | "boolean" | "null")
                ) {
                    return Err(Error::InvalidInput);
                }
            }
            "properties" => {
                for (name, child) in value.as_object().ok_or(Error::InvalidInput)? {
                    if name.is_empty() || name.len() > 128 {
                        return Err(Error::InvalidInput);
                    }
                    bounded_schema(child, depth + 1, nodes)?;
                }
            }
            "items" => bounded_schema(value, depth + 1, nodes)?,
            "additionalProperties" => {
                if value != &Value::Bool(false) {
                    return Err(Error::InvalidInput);
                }
            }
            "required" | "enum" | "const" | "minItems" | "maxItems" | "minLength" | "maxLength"
            | "minimum" | "maximum" | "title" | "description" => (),
            _ => return Err(Error::InvalidInput),
        }
    }
    Ok(())
}
fn output_structure(value: &Value, max_rows: usize, depth: usize) -> Result<(), Error> {
    if depth > 16 {
        return Err(Error::InvalidInput);
    }
    match value {
        Value::Array(values) => {
            if values.len() > max_rows {
                return Err(Error::InvalidInput);
            }
            for value in values {
                output_structure(value, max_rows, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                output_structure(value, max_rows, depth + 1)?;
            }
        }
        _ => (),
    }
    Ok(())
}
