//! Agent-native declaration and server-owned field mapping.
use crate::Error;
use rss_mdm_agent_wire::runtime::NativeCollectionPlan;
use rss_mdm_agent_wire::runtime::{AgentCollectionMapping, NativeMissing};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Construction input. Native protocol types stay owned by agent-wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCollectionSpec {
    /// Frozen platform prerequisites, checked by the same preview/Offer/Start admission.
    pub applicability: crate::Applicability,
    /// Immutable native execution plan.
    pub plan: NativeCollectionPlan,
    /// Unique field bindings, resolved against Inventory at publication.
    pub mappings: BTreeMap<String, AgentCollectionMapping>,
}
/// Validated declaration with an immutable canonical artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
        spec.applicability.validate()?;
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
            if binding.counter_normalization.is_some() {
                use rss_mdm_agent_wire::runtime::{
                    NativeQueryDefinition as Q, PerformanceSection as S,
                };
                if !matches!(
                    query.definition,
                    Q::WindowsPerformance {
                        section: S::Network
                    } | Q::MacosPerformance {
                        section: S::Network
                    }
                ) || binding.missing != NativeMissing::Missing
                {
                    return Err(Error::InvalidInput);
                }
            }
            binding.validate_query(&spec.plan)?;
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
