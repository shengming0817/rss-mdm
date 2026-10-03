//! Platform-owned lifecycle inputs; shared flow envelopes do not invent Apple commands.
use super::{
    ddm::{AssetInput, DeclarationInput},
    input::CommandInput,
    profiles::ProfileInput,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Immutable native operation input. DDM synchronization has no command ACK lifecycle.
#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Request {
    /// A command whose fields are checked by the frozen official schema.
    Command { command: CommandInput },
    /// Install or replace a native profile with independently identified payloads.
    InstallProfile { profile: ProfileInput },
    /// Remove an owned profile, identifying both its native name and expected version UUID.
    RemoveProfile { identifier: String, uuid: Uuid },
    /// Replace the caller's desired declaration set. Omission withdraws that owner's declaration.
    Declarations {
        declarations: Vec<DeclarationInput>,
        assets: Vec<AssetInput>,
    },
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppleNativeRequest([REDACTED])")
    }
}
