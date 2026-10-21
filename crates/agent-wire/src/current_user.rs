//! Device-bound enterprise login; OS accounts are separate Inventory observations.
use crate::runtime::{SelfServiceUser, WireError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
/// One explicit login/switch or logout operation. Identity is never caller-selected.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentUserChange {
    /// Stable identity retained through an unknown response.
    pub operation_id: Uuid,
    /// Revision read from this device before making the change.
    pub expected_revision: u64,
}
impl CurrentUserChange {
    /// Reject invalid operation identities and exhausted revisions.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.operation_id.is_nil() || self.expected_revision >= i64::MAX as u64 {
            Err(WireError::InvalidValue)
        } else {
            Ok(())
        }
    }
}
/// Server-verified enterprise session state, independent of network presence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CurrentUserState {
    /// No enterprise user is bound.
    Unbound,
    /// The exact enterprise session and device registration remain valid.
    Active,
    /// The retained session or device registration is no longer valid.
    Invalidated,
}
/// Public current-user projection. Session locators and secrets are never exposed.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentUser {
    /// Device-scoped CAS revision, retained after logout.
    pub revision: u64,
    /// Current verified state; active does not mean the device is online.
    pub state: CurrentUserState,
    /// Same backend user identity used for asset ownership, when verified.
    pub user: Option<SelfServiceUser>,
    /// Server UTC Unix seconds of the last explicit binding change.
    pub confirmed_at: Option<i64>,
}
