//! Collection inputs contain product facts; executable platform plans stay in channels.
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::{Architecture, Frequency, Platform, schedule::Schedule};
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollectionInput {
    pub platform: Platform,
    pub architecture: Architecture,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
/// Frozen native Agent input, independent of script permissions and profiles.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenAgent {
    pub fields: Vec<rss_mdm_inventory::FieldDefinition>,
    pub input: CollectionInput,
    pub resource: wire::TaskResource,
    pub definition: r::AgentCollectionDefinition,
    pub resource_digest: [u8; 32],
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenNative {
    pub input: CollectionInput,
    pub definition: r::NativeCollectionDefinition,
    pub collection: rss_mdm_inventory::CollectionDefinition,
    pub resource_digest: [u8; 32],
    pub permissions: Vec<rss_mdm_authorization_service::Permission>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Published {
    AgentCollection {
        action: Box<FrozenAgent>,
        frequency: Frequency,
    },
    NativeCollection {
        action: Box<FrozenNative>,
        frequency: Frequency,
    },
}
impl Published {
    pub fn input(&self) -> &CollectionInput {
        match self {
            Self::AgentCollection { action, .. } => &action.input,
            Self::NativeCollection { action, .. } => &action.input,
        }
    }
    pub fn frequency(&self) -> Frequency {
        match self {
            Self::AgentCollection { frequency, .. } | Self::NativeCollection { frequency, .. } => {
                *frequency
            }
        }
    }
    pub fn channel(&self) -> rss_mdm_inventory::Channel {
        match self {
            Self::AgentCollection { .. } => rss_mdm_inventory::Channel::Agent,
            Self::NativeCollection { .. } => rss_mdm_inventory::Channel::Mdm,
        }
    }
}
