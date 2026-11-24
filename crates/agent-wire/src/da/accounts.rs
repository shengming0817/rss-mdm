//! Direct delivery of a frozen local account operation over the DA device listener.
use crate::runtime as w;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Execution platform selected by this client before the server chooses a candidate.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountClaim {
    /// Filters offers; the current DA registration and frozen target grant authority.
    pub platform: w::TaskPlatform,
}

/// Observations stored with standalone DA account operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AccountEffect {
    /// A directly authorized macOS Create was read back. PSSO readiness is independent.
    MacAccountCreated {
        /// Stable native identity read from the created account.
        generated_uid: Uuid,
        /// Actual privilege, including when it differs from the requested role.
        role: w::AccessRole,
        /// Account-specific Secure Token observation.
        secure_token: w::AccessObservation,
        /// Independently observed Apple silicon volume ownership.
        volume_owner: w::AccessObservation,
        /// Independently observed FileVault unlock eligibility.
        filevault_unlock: w::AccessObservation,
    },
    /// Common configuration, refusal, unknown or cleanup observation.
    #[serde(untagged)]
    Access(w::AccessEffect),
}
impl From<w::AccessEffect> for AccountEffect {
    fn from(v: w::AccessEffect) -> Self {
        Self::Access(v)
    }
}
impl From<w::AccessResult> for AccountResult {
    fn from(v: w::AccessResult) -> Self {
        let w::AccessResult {
            binding_id,
            binding_generation,
            revision,
            definition_digest,
            effect,
        } = v;
        Self {
            binding_id,
            binding_generation,
            revision,
            definition_digest,
            effect: effect.into(),
        }
    }
}
/// DA uses the same attempt coordinates for native creation and configuration observations.
pub type AccountResult = w::AccessResult<AccountEffect>;

/// Coordinates to journal before acknowledging an offered account operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountOffer {
    /// Original binding management operation.
    pub operation_id: Uuid,
    /// Server-assigned delivery and attempt.
    pub task_id: Uuid,
    /// Stable across interruption.
    pub attempt_id: Uuid,
    /// Exact desired binding.
    pub binding_id: Uuid,
    /// Frozen desired state fingerprint.
    pub definition_digest: [u8; 32],
}

/// Evidence about one journaled attempt.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountEvent {
    /// Unique event key reused for exact retries.
    pub event_id: Uuid,
    /// Attempt from the offer.
    pub attempt_id: Uuid,
    /// Fingerprint from the offer.
    pub definition_digest: [u8; 32],
    /// Device observation.
    pub event: AccountObservation,
}

/// Closed set of local account observations accepted by DA.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AccountObservation {
    /// The device journaled the offer and requests execution permission.
    Received,
    /// The durable device journal proves that native execution never began before the permit expired.
    NotStarted {
        /// Expiry of the exact unused permit in the local journal.
        #[serde(rename = "expiresAt")]
        expires_at: i64,
    },
    /// The original create journal was stopped and proves it left no local account.
    CreateAbsent {
        /// Exact issued permit after its execution window closed.
        #[serde(rename = "expiresAt")]
        expires_at: i64,
    },
    /// Stable local account established by the device.
    Prepared(w::AccessPrepared),
    /// Encrypted RSS factor recovery material.
    Escrow(w::CredentialEscrow),
    /// Actual local observation, including unknown and cleanup.
    Result(AccountResult),
}

/// Receipt of the exact device event.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountSettlement {
    /// The settled event.
    pub event_id: Uuid,
    /// Read-only expiry originally issued for this event, including after expiry or withdrawal.
    pub issued_expires_at: Option<i64>,
    /// Bounded Start permission, returned only for a current received event.
    pub permit: Option<w::AccessTaskSpec>,
    /// Exact custody acknowledgement for encrypted material.
    pub receipt: Option<w::CredentialReceipt>,
}
