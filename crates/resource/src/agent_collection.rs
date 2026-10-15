//! Agent-native declaration and server-owned field mapping.
use crate::{Error, ValueMapping};
use rss_mdm_agent_wire::runtime::{NativeCardinality, NativeCollectionPlan, NativeType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Complete absence handling, never applied to failed or truncated queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCollectionMapping {
    /// Stable query identity.
    pub query: String,
    /// Existing pointer and conversion semantics.
    pub mapping: ValueMapping,
    /// Explicit handling of complete absence.
    pub missing: NativeMissing,
}
/// Construction input. Native protocol types stay owned by agent-wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCollectionSpec {
    /// Immutable native execution plan.
    pub plan: NativeCollectionPlan,
    /// Unique field bindings, resolved against Inventory at publication.
    pub mappings: BTreeMap<String, AgentCollectionMapping>,
}
/// Validated declaration with an immutable canonical artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AgentCollectionSpec", into = "AgentCollectionSpec")]
pub struct AgentCollectionDefinition(AgentCollectionSpec);
impl From<AgentCollectionDefinition> for AgentCollectionSpec {
    fn from(v: AgentCollectionDefinition) -> Self {
        v.0
    }
}
impl TryFrom<AgentCollectionSpec> for AgentCollectionDefinition {
    type Error = Error;
    fn try_from(v: AgentCollectionSpec) -> Result<Self, Error> {
        Self::new(v)
    }
}
impl AgentCollectionDefinition {
    /// Validate static mappings; field permissions and Inventory types are checked by publication.
    pub fn new(spec: AgentCollectionSpec) -> Result<Self, Error> {
        if spec.mappings.is_empty() || spec.mappings.len() > 64 {
            return Err(Error::InvalidInput);
        }
        for (field, binding) in &spec.mappings {
            rss_mdm_agent_wire::runtime::FieldKey::parse(field).map_err(|_| Error::InvalidInput)?;
            if !["device.", "custom.", "channel."]
                .iter()
                .any(|p| field.starts_with(p))
            {
                return Err(Error::InvalidInput);
            }
            binding.mapping.validate()?;
            let query = spec
                .plan
                .spec()
                .queries
                .get(&binding.query)
                .ok_or(Error::InvalidInput)?;
            let props = query.definition.properties();
            validate_mapping(
                &binding.mapping,
                &props,
                query.cardinality == NativeCardinality::List,
            )?;
        }
        Ok(Self(spec))
    }
    /// Frozen inputs.
    pub fn spec(&self) -> &AgentCollectionSpec {
        &self.0
    }
    /// Require the exact operating system declared by the native plan.
    pub fn validate_platform(&self, p: crate::Platform) -> Result<(), Error> {
        if matches!(
            (p, self.0.plan.platform()),
            (
                crate::Platform::Windows,
                rss_mdm_agent_wire::runtime::TaskPlatform::Windows
            ) | (
                crate::Platform::MacOS,
                rss_mdm_agent_wire::runtime::TaskPlatform::Macos
            )
        ) {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
    /// Exact content bytes stored and verified by Resource.
    pub fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("closed agent collection")
    }
}
fn validate_mapping(
    m: &ValueMapping,
    p: &BTreeMap<String, NativeType>,
    list: bool,
) -> Result<(), Error> {
    if list || !m.columns.is_empty() {
        if !m.pointer.is_empty()
            || m.columns.is_empty()
            || m.conversion != crate::Conversion::Identity
        {
            return Err(Error::InvalidInput);
        }
        for column in m.columns.values() {
            validate_mapping(column, p, false)?;
        }
        return Ok(());
    }
    let key = m.pointer.strip_prefix('/').ok_or(Error::InvalidInput)?;
    let ty = p.get(key).ok_or(Error::InvalidInput)?;
    if !m.columns.is_empty() {
        return Err(Error::InvalidInput);
    }
    use crate::Conversion;
    if match &m.conversion {
        Conversion::Identity => false,
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
        return Err(Error::InvalidInput);
    }
    Ok(())
}
