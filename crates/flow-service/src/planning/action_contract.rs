//! Frozen execution contract. It deliberately excludes authors, approval rows and Scope internals.
use crate::Error;
use rss_mdm_agent_wire as wire;
use rss_mdm_policy::schedule::Schedule;
pub use rss_mdm_policy::{Architecture, Platform};
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionInput {
    pub platform: Platform,
    pub architecture: Architecture,
    pub parameters: Value,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenAction {
    pub input: ExecutionInput,
    pub definition: r::ScriptDefinition,
    pub resource_digest: [u8; 32],
    pub artifact_reference: String,
    pub content: wire::TaskContent,
}
impl FrozenAction {
    pub fn artifact(&self) -> Result<r::Artifact, Error> {
        r::Artifact::new(
            r::Id::new(&self.artifact_reference).map_err(|_| Error::Malformed)?,
            self.content.length,
            r::Digest::from_bytes(self.content.sha256),
        )
        .map_err(|_| Error::Malformed)
    }
}
/// Enterprise software input frozen at Policy publication, before per-device admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FrozenSoftwareAction {
    pub resource: String,
    pub version: String,
    pub variants: BTreeMap<rss_mdm_policy::SoftwareTarget, String>,
    pub resource_digest: [u8; 32],
    pub admission_operation: uuid::Uuid,
    pub intent: rss_mdm_policy::SoftwareIntent,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
