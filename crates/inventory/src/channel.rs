//! Inventory channel observations, distinct from delivery or registration proof.
use uuid::Uuid;
/// Sealed native inventory evidence used to qualify an Agent installation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvidence {
    /// Digest of the exact detector catalog used by this observation.
    pub catalog_digest: [u8; 32],
    /// Whether the native observer found provisioning evidence.
    pub provisioned: bool,
    /// Package identities whose presence was actually checked.
    pub checked_identities: Vec<String>,
    /// Observed package identity, empty when absent.
    pub identity: String,
    /// Observed publisher when available.
    pub publisher: Option<String>,
    /// Observed installed version when available.
    pub version: Option<String>,
    /// Observed architecture when available.
    pub architecture: Option<String>,
}
impl AgentEvidence {
    /// Whether this observation checked the exact detector identity.
    pub fn matches(&self, identity: &str) -> bool {
        self.checked_identities
            .iter()
            .any(|candidate| candidate == identity)
    }
}
/// Current sealed observation from Inventory.
#[derive(Clone, Debug)]
pub struct Current {
    /// Current normalized channel state.
    pub state: String,
    /// Original sealed collection snapshot.
    pub snapshot: Uuid,
    /// Snapshot receipt time in Unix seconds.
    pub received_at: i64,
    /// Native detection evidence when supplied.
    pub evidence: Option<AgentEvidence>,
}

/// Observation readiness is distinct from a negative or unknown channel fact.
#[derive(Clone, Debug)]
pub enum Observation {
    /// The current sealed snapshot is projected and consumable.
    Ready(Current),
    /// A sealed report exists but its projection is not yet consumable.
    ProjectionPending {
        /// Detection evidence retained while projection is pending.
        evidence: Option<AgentEvidence>,
    },
    /// No current observation can qualify the channel.
    Unavailable,
}
