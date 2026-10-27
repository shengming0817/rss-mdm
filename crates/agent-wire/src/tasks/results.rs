//! Evidence bound to every frozen software step, with independent native detection.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Exact native detector identity. Registration and provisioning cannot share an identity variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
        #[schemars(extend("minLength" = 1, "maxLength" = 38, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
        product_code: String,
    },
    /// Exact PackageInstaller receipt.
    PkgReceipt {
        /// Receipt identifier.
        #[schemars(extend("minLength" = 1, "maxLength" = 255, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
        receipt: String,
    },
    /// Exact copied application at its managed destination.
    MacApplication {
        /// Bundle identifier.
        #[schemars(extend("minLength" = 1, "maxLength" = 255, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
        bundle_id: String,
        /// Approved target basename.
        #[schemars(extend("minLength" = 1, "maxLength" = 255, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
        target_name: String,
    },
    /// Exact value under its declared hive scope.
    Registry {
        /// Native hive scope.
        scope: SoftwareTaskScope,
        /// Literal key.
        #[schemars(extend("minLength" = 1, "maxLength" = 1024, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
        key: String,
        /// Literal value name.
        #[schemars(extend("minLength" = 1, "maxLength" = 255, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
        value: String,
    },
    /// Exact protected file under its scope.
    File {
        /// Native target scope.
        scope: SoftwareTaskScope,
        /// Approved path.
        #[schemars(extend("minLength" = 1, "maxLength" = 1024, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
        path: String,
    },
    /// Output of the exact approved detection script, bound by the step digest.
    ControlledDetector {
        /// Immutable material/member reference.
        #[schemars(extend("minLength" = 1, "maxLength" = 1024, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
        #[schemars(length(min = 1, max = 1024), regex(pattern = "^[^\\x00-\\x1f\\x7f]+$"))]
        version: String,
        /// Digest of retained local detection evidence.
        #[schemars(schema_with = "crate::runtime::nonzero_digest_schema")]
        evidence_sha256: [u8; 32],
        /// Native observation time, in Unix seconds.
        #[schemars(range(min = 1, max = i64::MAX))]
        observed_at: i64,
    },
    /// The exact identity is absent under the independently queried target.
    Absent {
        /// Digest of retained absence evidence.
        #[schemars(schema_with = "crate::runtime::nonzero_digest_schema")]
        evidence_sha256: [u8; 32],
        /// Native observation time, in Unix seconds.
        #[schemars(range(min = 1, max = i64::MAX))]
        observed_at: i64,
    },
    /// Detection did not establish a state; no version/absence claim is permitted.
    Unknown {
        /// Bounded reason for the failed native query.
        #[schemars(length(min = 1, max = 4096), regex(pattern = "^[^\\x00-\\x1f\\x7f]+$"))]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
        #[schemars(extend("minimum" = -2147483648i64, "maximum" = 2147483647))]
        code: i32,
    },
    /// No complete process return code was captured.
    Failed {
        /// Closed execution failure category.
        failure: TaskFailure,
    },
}
/// Complete evidence for one signed local step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schemars(rename = "SoftwareStepResult")]
pub struct SoftwareStepResult<D = TaskDiagnostics> {
    /// Exact producer node in this task and attempt.
    #[schemars(schema_with = "crate::runtime::nonzero_digest_schema")]
    pub step_id: [u8; 32],
    /// Zero-based position in the signed dependency plan.
    #[schemars(extend("minimum" = 0, "maximum" = 31))]
    pub index: u8,
    /// SHA-256 of this exact signed step, including material, identity and target.
    #[schemars(schema_with = "crate::runtime::nonzero_digest_schema")]
    pub step_digest: [u8; 32],
    /// Exact effect target and login generation from the step.
    pub target: SoftwareExecutionTarget,
    /// Exact ecosystem package coordinate from the step.
    #[schemars(extend("minLength" = 1, "maxLength" = 1024, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
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
    pub diagnostics: D,
}
/// A complete result for the signed task. The product determines its trusted projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schemars(rename = "SoftwareTaskResult")]
pub struct SoftwareTaskResult<D = TaskDiagnostics> {
    /// Requested root operation.
    pub intent: SoftwareTaskIntent,
    /// Exact digest of the signed dependency plan.
    #[schemars(schema_with = "crate::runtime::nonzero_digest_schema")]
    pub definition_digest: [u8; 32],
    /// One result for every signed step, in execution order; skipped steps remain explicit.
    #[schemars(extend("minItems" = 1, "maxItems" = 32))]
    pub steps: Vec<SoftwareStepResult<D>>,
}
impl SoftwareTaskResult {
    /// Reject malformed or incoherent observations before product projection.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.definition_digest == [0; 32] || self.steps.is_empty() || self.steps.len() > 32 {
            return Err(WireError::InvalidValue);
        }
        let mut nodes = std::collections::BTreeSet::new();
        for (index, result) in self.steps.iter().enumerate() {
            if result.step_id == [0; 32]
                || !nodes.insert(result.step_id)
                || result.index as usize != index
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detection_schema_preserves_native_evidence_boundaries() {
        let schema =
            serde_json::to_value(schemars::schema_for!(SoftwareDetectionObservation)).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let present = serde_json::json!({"state":"present","version":"1","evidenceSha256":vec![1;32],"observedAt":1});
        assert!(validator.is_valid(&present));
        for (field, invalid) in [
            ("version", serde_json::json!("")),
            ("version", serde_json::json!("a".repeat(1025))),
            ("version", serde_json::json!("bad\0version")),
            ("evidenceSha256", serde_json::json!(vec![0; 32])),
            ("observedAt", serde_json::json!(0)),
        ] {
            let mut value = present.clone();
            value[field] = invalid;
            assert!(!validator.is_valid(&value), "{value}");
            assert!(
                serde_json::from_value::<SoftwareDetectionObservation>(value)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        for diagnostic in ["", "bad\0diagnostic"] {
            let value = serde_json::json!({"state":"unknown","diagnostic":diagnostic});
            assert!(!validator.is_valid(&value));
            assert!(
                serde_json::from_value::<SoftwareDetectionObservation>(value)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
}
