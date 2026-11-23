//! DA mTLS credential events and secret-free settlement acknowledgements.
use crate::runtime as wire;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Persistent outcome of a targeted DA credential operation.
pub enum CredentialState {
    /// The operation may be claimed by the current registration.
    Accepted,
    /// Custody accepted the observation and awaits an application acknowledgement.
    PendingApplication,
    /// A verification operation is resolving the original uncertain attempt.
    Reconciling,
    /// Another operation replaced this attempt before custody.
    Superseded,
    /// Independent verification confirmed the previous credential.
    Unchanged,
    /// The original binding generation has been retired.
    Retired,
    /// The selected material was confirmed current on the device.
    Applied,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "event",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
/// Device evidence for an exact DA credential execution.
pub enum CredentialEvent {
    /// Submit encrypted material for this attempt.
    Escrow {
        /// Attempt issued by the server in the claimed task.
        attempt_id: Uuid,
        /// Encrypted credential envelope and its frozen coordinates.
        value: wire::CredentialEscrow,
    },
    /// Confirm an observed credential with its exact custody receipt.
    Applied {
        /// Attempt issued by the server in the claimed task.
        attempt_id: Uuid,
        /// Digest of the definition from the original claim.
        definition_digest: [u8; 32],
        /// Previously issued custody receipt for the observed version.
        receipt: wire::CredentialReceipt,
    },
}

/// Result of settling an event on the exact DA operation.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSettlement {
    /// Operation addressed by the device event.
    pub operation_id: Uuid,
    /// Current settlement state.
    pub state: CredentialState,
    /// Exact stored credential version when custody has completed.
    pub receipt: Option<wire::CredentialReceipt>,
}
