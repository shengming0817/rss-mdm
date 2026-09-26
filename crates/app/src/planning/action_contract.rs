//! Frozen execution contract. It deliberately excludes authors, approval rows and Scope internals.
use super::action_schedule::Schedule;
use crate::Error;
use rss_mdm_agent_wire as wire;
use rss_mdm_resource as r;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Platform {
    Windows,
    Macos,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutionInput {
    pub platform: Platform,
    pub architecture: Architecture,
    pub parameters: Value,
    pub schedule: Schedule,
    pub run_lifetime_seconds: u32,
}
#[derive(Clone, Debug)]
pub(crate) struct ExecutionTargets {
    pub devices: Vec<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct FrozenAction {
    pub input: ExecutionInput,
    pub targets: ExecutionTargets,
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
