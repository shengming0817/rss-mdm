use rss_mdm_agent_wire::runtime as w;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentCollection {
    pub native: Option<w::NativeCollectionResult>,
    pub queries: BTreeMap<String, NativeQuerySummary>,
    pub plan_digest: [u8; 32],
    pub output_reference: w::ScriptOutputReference,
    pub trusted: bool,
    pub received_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeQuerySummary {
    pub query_digest: [u8; 32],
    pub collected_at: i64,
    pub status: w::NativeQueryStatus,
    pub enumeration_complete: bool,
    pub row_count: u32,
}
