//! Persisted execution evidence uses its real Agent or native owner, including null/omission semantics.
use rss_mdm_agent_wire::runtime as w;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum RunResult {
    Credential(w::CredentialResult),
    CredentialRecovery(CredentialRecovery),
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRecovery {
    pub effect: w::CredentialRecoveryOutcome,
    pub recovered_by_task: Uuid,
    pub recovered_by_attempt: Option<Uuid>,
}
