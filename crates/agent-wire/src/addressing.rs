//! Enterprise Policy addresses. Names locate objects and never confer authority.
use crate::runtime::WireError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Tenant-local canonical Policy alias.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct PolicyAlias(String);
impl PolicyAlias {
    /// Normalize user input to its single ASCII address representation.
    pub fn parse(value: &str) -> Result<Self, WireError> {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(WireError::InvalidValue);
        }
        Ok(Self(value))
    }
    /// Canonical value used by the unique storage index.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for PolicyAlias {
    type Error = WireError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}
impl From<PolicyAlias> for String {
    fn from(value: PolicyAlias) -> Self {
        value.0
    }
}
/// Immutable tool name, independent of configuration and execution versions.
pub fn policy_tool_name(id: Uuid) -> String {
    format!("policy_{}", id.simple())
}
/// Explicit exact address in the authenticated tenant's Policy namespace.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilitySelector {
    /// Canonical Policy identity.
    Id {
        /// Object ID.
        id: Uuid,
    },
    /// Server-generated tool name.
    ToolName {
        /// Complete canonical name.
        name: String,
    },
    /// Administrator-controlled unique alias.
    Alias {
        /// Canonical tenant-local alias.
        alias: PolicyAlias,
    },
}
impl CapabilitySelector {
    /// Decode identity addresses; aliases require an exact authorized storage lookup.
    pub fn policy_id(&self) -> Result<Option<Uuid>, WireError> {
        let id = match self {
            Self::Id { id } => *id,
            Self::ToolName { name } => {
                let id = name
                    .strip_prefix("policy_")
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .ok_or(WireError::InvalidValue)?;
                if policy_tool_name(id) != *name {
                    return Err(WireError::InvalidValue);
                }
                id
            }
            Self::Alias { .. } => return Ok(None),
        };
        if id.is_nil() {
            return Err(WireError::InvalidValue);
        }
        Ok(Some(id))
    }
}
/// Cross-endpoint capability identity and interface, never an execution permit.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescriptor {
    /// Stable Policy capability ID.
    pub id: Uuid,
    /// Object namespace.
    pub object_type: CapabilityObject,
    /// Server-owned stable invocation name.
    pub tool_name: String,
    /// Optional administrator address.
    pub alias: Option<PolicyAlias>,
    /// Actual scope owner; membership is rechecked by execution.
    pub scope: Uuid,
    /// Product service instance.
    pub instance: String,
    /// Tenant owning this capability.
    pub tenant: Uuid,
    /// Current configuration revision, for information only.
    pub revision: u64,
    /// Material version observed while resolving, not a call precondition.
    pub version: Uuid,
    /// Operations supported in this interface.
    pub operations: Vec<CapabilityOperation>,
    /// Schema for caller-provided parameters.
    #[schemars(schema_with = "crate::schema_values::schema_document")]
    pub input_schema: serde_json::Value,
    /// Schema of the operation result.
    #[schemars(schema_with = "crate::schema_values::schema_document")]
    pub output_schema: serde_json::Value,
}
/// Enterprise objects currently exposed through this contract.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityObject {
    /// A Policy, including its self-service view.
    Policy,
}
/// Operations available through the authenticated interface.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityOperation {
    /// Read the Policy.
    Read,
    /// Invoke its published self-service task.
    Invoke,
}
/// Exact self-service discovery, authenticated like the directory.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfServiceResolve {
    /// Trusted caller classification.
    pub source: crate::runtime::SelfServiceCaller,
    /// One explicit address.
    pub selector: CapabilitySelector,
}

/// Tenant-local event name shared by any number of Policies; never an object alias.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct PolicyEventName(String);
impl PolicyEventName {
    /// Use the same canonical spelling as other enterprise names.
    pub fn parse(value: &str) -> Result<Self, WireError> {
        Ok(Self(PolicyAlias::parse(value)?.as_str().to_owned()))
    }
    /// Canonical event name used by the Policy index.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for PolicyEventName {
    type Error = WireError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}
impl From<PolicyEventName> for String {
    fn from(value: PolicyEventName) -> Self {
        value.0
    }
}
