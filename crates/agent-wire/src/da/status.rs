//! Bounded, secret-free DA diagnostics. Reports cannot settle authentication effects.
use super::SourceState;
use crate::runtime::WireError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identity must match the authenticated transport and current registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportIdentity {
    /// Product installation instance.
    pub service_id: Uuid,
    /// Owning tenant.
    pub tenant: Uuid,
    /// Current DA registration.
    pub registration: Uuid,
    /// Current positive registration generation.
    pub generation: i64,
}
/// A reported diagnostic, never proof that login is permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// No observation is available.
    Unknown,
    /// Device reports readiness.
    Ready,
    /// Device reports a degraded capability.
    Degraded,
    /// Device reports that a prerequisite blocks operation.
    Blocked,
}
/// Closed diagnostic classes deliberately exclude arbitrary process output and secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Diagnostic {
    /// Unsupported platform capability.
    Unsupported,
    /// Local permission missing.
    PermissionDenied,
    /// Configuration or trust failed validation.
    InvalidConfiguration,
    /// Native source unavailable.
    SourceUnavailable,
    /// Conflicting sources.
    SourceConflict,
    /// A binding or factor is not ready.
    FactorUnavailable,
}
/// Complete diagnostic snapshot; sequence is the idempotency key within its registration.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusReport {
    /// Authenticated identity coordinates.
    pub identity: ReportIdentity,
    /// Positive, monotonically increasing per registration generation.
    pub sequence: i64,
    /// Device time is descriptive only.
    pub observed_at: Option<i64>,
    /// Bounded version label, not an executable capability declaration.
    pub client_version: String,
    /// Current protocol format, one.
    pub contract_version: u8,
    /// Binding readiness claimed by the device.
    pub binding: Health,
    /// Factor readiness claimed by the device.
    pub factor: Health,
    /// Overall health claimed by the device.
    pub health: Health,
    /// Last configuration digest reported by the device.
    pub configuration_digest: Option<String>,
    /// Bounded closed diagnostic classes.
    pub errors: Vec<Diagnostic>,
}
impl StatusReport {
    /// Validate the bounded public contract before accessing persistence.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.identity.service_id.is_nil()
            || self.identity.tenant.is_nil()
            || self.identity.registration.is_nil()
            || self.identity.generation < 1
            || self.sequence < 1
            || self.observed_at.is_some_and(|v| v < 0)
            || self.contract_version != 1
            || self.client_version.is_empty()
            || self.client_version.len() > 128
            || self.client_version.chars().any(char::is_control)
            || self.errors.len() > 16
            || self
                .configuration_digest
                .as_ref()
                .is_some_and(|v| !valid_digest(v))
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
/// Validate canonical SHA-256 text.
pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Application observations are independent facts, not an inferred success chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationState {
    /// Received by the reporting device.
    Received,
    /// Device claims validation succeeded.
    Validated,
    /// Device claims local application succeeded.
    Applied,
    /// Device rejected the candidate.
    Rejected,
    /// Local application outcome is unknown.
    Unknown,
}
/// A single source referenced by an application report, without a caller-controlled trust flag.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportedSource {
    /// Exact export operation.
    pub artifact: Uuid,
    /// Exact inner payload digest.
    pub digest: String,
    /// Actual delivery claimed by the device.
    pub delivery: super::DeliveryPermission,
    /// Local source read/validation result.
    pub state: SourceState,
}
/// Configuration application report; it cannot acknowledge signing-key installation.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationReport {
    /// Current authenticated registration.
    pub identity: ReportIdentity,
    /// Stable report operation for exact replay.
    pub operation_id: Uuid,
    /// Monotonic application-report sequence, separate from periodic status.
    pub sequence: i64,
    /// Original signing operation for the selected candidate.
    pub artifact: Uuid,
    /// Expected inner payload digest.
    pub digest: String,
    /// Exact contributing source set.
    pub sources: Vec<ReportedSource>,
    /// Device-reported observation.
    pub state: ApplicationState,
    /// Optional closed rejection reason.
    pub error: Option<Diagnostic>,
}
impl ReportIdentity {
    /// Check the identity shape; the authenticated owner must still compare all coordinates.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.service_id.is_nil()
            || self.tenant.is_nil()
            || self.registration.is_nil()
            || self.generation < 1
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
impl ApplicationReport {
    /// Bound untrusted source claims and require exact, nonduplicated artifact references.
    pub fn validate(&self) -> Result<(), WireError> {
        self.identity.validate()?;
        if self.operation_id.is_nil()
            || self.artifact.is_nil()
            || self.sequence < 1
            || !valid_digest(&self.digest)
            || self.sources.len() > 16
        {
            return Err(WireError::InvalidValue);
        }
        let mut seen = std::collections::BTreeSet::new();
        for source in &self.sources {
            if source.artifact.is_nil()
                || !valid_digest(&source.digest)
                || !seen.insert(source.artifact)
            {
                return Err(WireError::InvalidValue);
            }
        }
        Ok(())
    }
}
