//! Evidence bound to every frozen software step, with independent native detection.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Exact native detector identity. Registration and provisioning cannot share an identity variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareObservedIdentity {
    /// Exact MSI product.
    MsiProduct {
        /// Canonical product GUID.
        product_code: String,
    },
    /// Exact PackageInstaller receipt.
    PkgReceipt {
        /// Receipt identifier.
        receipt: String,
    },
    /// Exact copied application at its managed destination.
    MacApplication {
        /// Bundle identifier.
        bundle_id: String,
        /// Approved target basename.
        target_name: String,
    },
    /// Exact value under its declared hive scope.
    Registry {
        /// Native hive scope.
        scope: SoftwareTaskScope,
        /// Literal key.
        key: String,
        /// Literal value name.
        value: String,
    },
    /// Exact protected file under its scope.
    File {
        /// Native target scope.
        scope: SoftwareTaskScope,
        /// Approved path.
        path: String,
    },
    /// Output of the exact approved detection script, bound by the step digest.
    ControlledDetector {
        /// Immutable material/member reference.
        entry: String,
    },
    /// Current-user package registration, never device provisioning.
    MsixRegistration {
        /// Exact full package identity.
        identity: SoftwareTaskMsixIdentity,
    },
    /// Future-user device provisioning, never current-user registration.
    MsixProvisioning {
        /// Exact full package identity.
        identity: SoftwareTaskMsixIdentity,
    },
}
/// Independent native observation; no process return code can construct a Present observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareDetectionObservation {
    /// The exact identity is present, at the observed version.
    Present {
        /// Observed ecosystem version.
        version: String,
        /// Digest of retained local detection evidence.
        evidence_sha256: [u8; 32],
        /// Native observation time, in Unix seconds.
        observed_at: i64,
    },
    /// The exact identity is absent under the independently queried target.
    Absent {
        /// Digest of retained absence evidence.
        evidence_sha256: [u8; 32],
        /// Native observation time, in Unix seconds.
        observed_at: i64,
    },
    /// Detection did not establish a state; no version/absence claim is permitted.
    Unknown {
        /// Bounded reason for the failed native query.
        diagnostic: String,
    },
}
impl SoftwareDetectionObservation {
    fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Present {
                version,
                evidence_sha256,
                observed_at,
            } => {
                if version.is_empty()
                    || version.len() > 1024
                    || version.chars().any(char::is_control)
                    || *evidence_sha256 == [0; 32]
                    || *observed_at < 1
                {
                    return Err(WireError::InvalidValue);
                }
            }
            Self::Absent {
                evidence_sha256,
                observed_at,
            } => {
                if *evidence_sha256 == [0; 32] || *observed_at < 1 {
                    return Err(WireError::InvalidValue);
                }
            }
            Self::Unknown { diagnostic } => {
                if diagnostic.is_empty() || diagnostic.len() > 4096 || diagnostic.contains('\0') {
                    return Err(WireError::InvalidValue);
                }
            }
        }
        Ok(())
    }
}
/// Process evidence is kept separate from effect detection and its exit-code classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareProcessObservation {
    /// A detector-only query or an already satisfied postcondition performed no mutation.
    NotRun,
    /// The approved native process produced this return code.
    Exited {
        /// Actual signed 32-bit process return code.
        code: i32,
    },
    /// No complete process return code was captured.
    Failed {
        /// Closed execution failure category.
        failure: TaskFailure,
    },
}
/// Complete evidence for one signed local step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareStepResult {
    /// Zero-based position in the signed dependency plan.
    pub index: u8,
    /// SHA-256 of this exact signed step, including material, identity and target.
    pub step_digest: [u8; 32],
    /// Exact effect target and login generation from the step.
    pub target: SoftwareExecutionTarget,
    /// Exact ecosystem package coordinate from the step.
    pub package: String,
    /// Independent native identity from the approved detector.
    pub identity: SoftwareObservedIdentity,
    /// Native observation before the attempted operation.
    pub before: SoftwareDetectionObservation,
    /// Native observation after the attempted operation or recovery query.
    pub after: SoftwareDetectionObservation,
    /// Process outcome; it never stands in for detection.
    pub process: SoftwareProcessObservation,
    /// Native reboot pending state after this step.
    pub reboot_required: bool,
    /// Bounded streams and process timing.
    pub diagnostics: TaskDiagnostics,
}
/// A complete result for the signed task. The product determines its trusted projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SoftwareTaskResult {
    /// Requested root operation.
    pub intent: SoftwareTaskIntent,
    /// Exact digest of the signed dependency plan.
    pub definition_digest: [u8; 32],
    /// One result for every signed step, in execution order; skipped steps remain explicit.
    pub steps: Vec<SoftwareStepResult>,
}
impl SoftwareTaskResult {
    /// Reject malformed or incoherent observations before product projection.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.definition_digest == [0; 32] || self.steps.is_empty() || self.steps.len() > 32 {
            return Err(WireError::InvalidValue);
        }
        for (index, result) in self.steps.iter().enumerate() {
            if result.index as usize != index
                || result.step_digest == [0; 32]
                || result.package.is_empty()
                || result.package.len() > 1024
                || result.package.chars().any(char::is_control)
            {
                return Err(WireError::InvalidValue);
            }
            if serde_json::to_vec(&result.identity)
                .map_err(|_| WireError::InvalidValue)?
                .len()
                > 8192
            {
                return Err(WireError::InvalidValue);
            }
            result.before.validate()?;
            result.after.validate()?;
            if let SoftwareExecutionTarget::User {
                identity,
                session_id,
            } = &result.target
                && (identity.is_empty()
                    || identity.len() > 184
                    || identity.chars().any(char::is_control)
                    || session_id.is_nil())
            {
                return Err(WireError::InvalidValue);
            }
            if matches!(result.process,SoftwareProcessObservation::Failed{failure} if result.diagnostics.failure()!=Some(failure))
            {
                return Err(WireError::InvalidValue);
            }
        }
        Ok(())
    }
}
impl SoftwareTaskStep {
    /// Exact evidence coordinate for this self-contained step.
    pub fn digest(&self) -> Result<[u8; 32], WireError> {
        Ok(
            sha2::Sha256::digest(serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?)
                .into(),
        )
    }
}
