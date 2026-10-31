//! Immutable Script inputs captured at publication.
use crate::Error;
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::{Architecture, Platform, schedule::Schedule};
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScriptInput {
    pub platform: Platform,
    pub architecture: Architecture,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenScript {
    pub input: ScriptInput,
    pub parameters: rss_mdm_policy::ParameterSources,
    pub resource: wire::TaskResource,
    pub definition: r::ScriptDefinition,
    pub collection: Option<rss_mdm_inventory::CollectionDefinition>,
    pub resource_digest: [u8; 32],
    pub artifact_reference: String,
    pub content: wire::TaskContent,
}
impl FrozenScript {
    pub fn artifact(&self) -> Result<r::Artifact, Error> {
        r::Artifact::new(
            r::Id::new(&self.artifact_reference).map_err(|_| Error::Malformed)?,
            self.content.length,
            r::Digest::from_bytes(self.content.sha256),
        )
        .map_err(|_| Error::Malformed)
    }
}
