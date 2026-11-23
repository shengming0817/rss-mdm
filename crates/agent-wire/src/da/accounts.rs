//! Direct delivery of a frozen Windows account operation over the DA device listener.
use crate::runtime as w;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Closed set of Windows account observations accepted by DA.
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
    NotStarted,
    /// Stable local account established by the device.
    Prepared(w::AccessPrepared),
    /// Encrypted RSS factor recovery material.
    Escrow(w::CredentialEscrow),
    /// Actual local observation, including unknown and cleanup.
    Result(w::AccessResult),
}

/// Receipt of the exact device event.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountSettlement {
    /// The settled event.
    pub event_id: Uuid,
    /// Bounded Start permission, returned only for a current received event.
    pub permit: Option<w::AccessTaskSpec>,
    /// Exact custody acknowledgement for encrypted material.
    pub receipt: Option<w::CredentialReceipt>,
}
