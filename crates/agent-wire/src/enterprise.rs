//! Native enterprise Broker proof contracts. Identity remains the authentication/session owner.
use crate::{
    platform_sso::PublicKey,
    runtime::{AccessLocalSession, Secret, WireError},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
/// Current independent enterprise protocol format.
pub const API_VERSION: u8 = 1;
/// Generated public contracts.
pub const SCHEMA_MANIFEST: &str = include_str!("../schema/enterprise/manifest.json");
/// Digest of generated schema bytes in manifest order.
pub const SCHEMA_FINGERPRINT: &str =
    "67bc06186ad06968202f5cc944ad551ac1a467f6d2967fc6e4f6ad54f1bfe8c6";

/// Register a user-held key against the exact applied Windows account binding.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRegistration {
    /// Existing business binding, never an account name.
    pub binding_id: Uuid,
    /// Personnel association generation.
    pub binding_generation: i64,
    /// Native factor generation.
    pub factor_generation: i64,
    /// Exact applied configuration revision.
    pub binding_revision: i64,
    /// P-256 public key only; no private material reaches the service.
    pub public_key: PublicKey,
    /// Unpadded base64url ES256 fixed-width signature of signing_bytes.
    pub signature: String,
}
impl KeyRegistration {
    /// Domain-separated public coordinates for proof of possession; does not prove UV or MFA.
    pub fn signing_bytes(
        &self,
        tenant: Uuid,
        instance: Uuid,
        principal: Uuid,
        operation: Uuid,
    ) -> Result<Vec<u8>, WireError> {
        if [tenant, instance, principal, operation, self.binding_id]
            .iter()
            .any(Uuid::is_nil)
            || self.binding_generation < 1
            || self.factor_generation < 1
            || self.binding_revision < 1
        {
            return Err(WireError::InvalidValue);
        }
        self.public_key.x963()?;
        serde_json::to_vec(&(
            "rss-mdm.enterprise.key.v1",
            tenant,
            instance,
            principal,
            operation,
            self.binding_id,
            self.binding_generation,
            self.factor_generation,
            self.binding_revision,
            &self.public_key,
        ))
        .map_err(|_| WireError::InvalidValue)
    }
}
/// Native signature over Identity's exact signing_payload, including RP purpose and nonce.
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProof {
    /// Unpadded base64url, exactly 64 decoded ES256 signature bytes.
    pub signature: String,
    /// Required native PSSO token on Mac; absent on Windows.
    pub access_token: Option<Secret>,
}
/// Begin one RP-specific business interaction; browser selects no callback or token audience.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Begin {
    /// Caller-chosen operation identity, preserved across status requests.
    pub operation_id: Uuid,
    /// Previously registered native account binding.
    pub binding_id: Uuid,
    /// Administrator-registered RP.
    pub relying_party: String,
}
/// One challenge delivered through the controlled desktop Broker.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    /// Product operation identity.
    pub operation_id: Uuid,
    /// Identity-owned challenge locator.
    pub challenge_id: Uuid,
    /// Identity nonce; not an authentication credential.
    pub nonce: String,
    /// Exact bytes to sign, without re-encoding JSON.
    pub signing_payload: Vec<u8>,
    /// Frozen native interactive session; rechecked on completion.
    pub local_session: AccessLocalSession,
    /// UTC expiration seconds.
    pub expires_at: i64,
}
/// Completion carries proof only for its original one-use challenge.
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Complete {
    /// Original operation identity.
    pub operation_id: Uuid,
    /// Identity challenge identity.
    pub challenge_id: Uuid,
    /// Original Identity nonce.
    pub nonce: String,
    /// Device signature and any required native protocol credential.
    pub proof: NativeProof,
}
/// Business interaction progress, separate from Identity session state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Intent committed; Identity challenge not yet durably attached.
    Preparing,
    /// Waiting for native user interaction.
    AwaitingProof,
    /// A single completion attempt owns the interaction.
    Completing,
    /// External exchange outcome is unknown; start a new interaction after reconciliation.
    Unknown,
    /// A bounded one-use backend handoff is available.
    Ready,
    /// The exact RP backend consumed the handoff.
    Consumed,
    /// User cancelled the interaction; no new RP session may consume it.
    Cancelled,
    /// The original deadline elapsed.
    Expired,
    /// A known failure did not establish an RP session.
    Failed,
}
/// Public status never exposes assertions, Identity credentials or IdP access tokens.
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    /// Original operation.
    pub operation_id: Uuid,
    /// Product progress.
    pub phase: Phase,
    /// Original deadline, never extended by polling.
    pub expires_at: i64,
    /// Fixed callback, present only for an available handoff.
    pub callback: Option<String>,
    /// One-use locator for the authenticated RP backend, never an Identity bearer token.
    pub continuation: Option<Secret>,
}
