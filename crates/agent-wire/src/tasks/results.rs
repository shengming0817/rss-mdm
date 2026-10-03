//! Evidence bound to every frozen software step, with independent native detection.
use super::*;
use serde::{Deserialize, Serialize};

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
    /// Independent postcondition matches an exact requested version or exact absence.
    pub fn satisfies(&self, intent: SoftwareTaskIntent, version: &str) -> bool {
        match (self, intent) {
            (
                Self::Present {
                    version: observed, ..
                },
                SoftwareTaskIntent::Install | SoftwareTaskIntent::Detect,
            ) => observed == version,
            (Self::Absent { .. }, SoftwareTaskIntent::Uninstall) => true,
            _ => false,
        }
    }
    /// Whether detection remains unresolved.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
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
/// Pure evidence assessment. This grants neither execution trust nor inventory/ownership facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftwareEvidenceAssessment {
    /// Every independently detected postcondition satisfies the signed task.
    Satisfied,
    /// Detection contradicts the task or reports a forbidden reboot.
    Unsatisfied,
    /// At least one independent observation remains unresolved.
    Unknown,
    /// Reboot is permitted and requires a later independent detection.
    RebootPending,
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
    /// Validate exact task association, then assess all independently detected postconditions.
    /// Current authorization, cancellation, deadlines and late-result eligibility belong to Execution.
    pub fn assess_for(&self, task: &SoftwareTaskSpec) -> Result<SoftwareEvidenceAssessment, WireError> {
        use SoftwareEvidenceAssessment as A;
        self.validate_association(task)?;
        if self.steps.iter().any(|step|step.after.is_unknown()) { return Ok(A::Unknown); }
        let reboot = self.steps.iter().any(|step|step.reboot_required);
        let reboot_allowed = self.steps.iter().zip(&task.steps)
            .all(|(result,step)| !result.reboot_required || step.action.reboot == SoftwareTaskReboot::Report);
        if reboot { return Ok(if reboot_allowed { A::RebootPending } else { A::Unsatisfied }); }
        let matches = self.steps.iter().zip(&task.steps).enumerate().all(|(index,(result,step))| {
            let intent = if index + 1 == task.steps.len() { task.intent } else { SoftwareTaskIntent::Install };
            result.after.satisfies(intent,&step.action.detected_version())
        });
        Ok(if matches { A::Satisfied } else { A::Unsatisfied })
    }
    /// Evidence from another step, target, package or native scope cannot satisfy this task.
    fn validate_association(&self, task: &SoftwareTaskSpec) -> Result<(), WireError> {
        self.validate()?;
        if self.definition_digest != task.definition_digest
            || self.intent != task.intent
            || self.steps.len() != task.steps.len()
        {
            return Err(WireError::InvalidValue);
        }
        for (result, step) in self.steps.iter().zip(&task.steps) {
            if result.step_digest != step.digest()?
                || result.target != step.target
                || result.package != step.action.package
                || result.identity != step.action.observed_identity()
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
        ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(self).map_err(|_| WireError::InvalidValue)?,
        )
        .as_ref()
        .try_into()
        .map_err(|_| WireError::InvalidValue)
    }
}
impl SoftwareTaskAction {
    /// The sole native identity mapping for independent result checks.
    pub fn observed_identity(&self) -> SoftwareObservedIdentity {
        use SoftwareTaskBehavior as B;
        let detection = |v: &SoftwareTaskDetection| match v {
            SoftwareTaskDetection::MsiProduct { product_code, .. } => {
                SoftwareObservedIdentity::MsiProduct {
                    product_code: product_code.clone(),
                }
            }
            SoftwareTaskDetection::PkgReceipt { receipt, .. } => {
                SoftwareObservedIdentity::PkgReceipt {
                    receipt: receipt.clone(),
                }
            }
            SoftwareTaskDetection::Registry {
                scope, key, value, ..
            } => SoftwareObservedIdentity::Registry {
                scope: *scope,
                key: key.clone(),
                value: value.clone(),
            },
            SoftwareTaskDetection::File { scope, path, .. } => SoftwareObservedIdentity::File {
                scope: *scope,
                path: path.clone(),
            },
            SoftwareTaskDetection::Script { command } => {
                SoftwareObservedIdentity::ControlledDetector {
                    entry: command.entry.clone(),
                }
            }
        };
        match &self.behavior {
            B::Msi(n) | B::Pkg(n) | B::Winget(n) | B::Brew(n) => detection(&n.detect),
            B::Exe(n) => detection(&n.detect),
            B::Bundle(n) => detection(&n.detect),
            B::Dmg(n) => match &n.payload {
                SoftwareTaskDmgPayload::AppCopy { application, .. } => {
                    SoftwareObservedIdentity::MacApplication {
                        bundle_id: application.bundle_id.clone(),
                        target_name: application.target_name.clone(),
                    }
                }
                SoftwareTaskDmgPayload::ContainedPkg { receipt, .. } => {
                    SoftwareObservedIdentity::PkgReceipt {
                        receipt: receipt.clone(),
                    }
                }
            },
            B::Msix(n) => match n.deployment {
                SoftwareTaskMsixDeployment::TargetUserRegistration { .. } => {
                    SoftwareObservedIdentity::MsixRegistration {
                        identity: n.identity.clone(),
                    }
                }
                SoftwareTaskMsixDeployment::DeviceProvisioning => {
                    SoftwareObservedIdentity::MsixProvisioning {
                        identity: n.identity.clone(),
                    }
                }
            },
        }
    }
    /// Exact expected version queried by the approved detector.
    pub fn detected_version(&self) -> String {
        use SoftwareTaskBehavior as B;
        let detection = |d: &SoftwareTaskDetection| match d {
            SoftwareTaskDetection::MsiProduct { version, .. }
            | SoftwareTaskDetection::PkgReceipt { version, .. }
            | SoftwareTaskDetection::Registry { version, .. }
            | SoftwareTaskDetection::File { version, .. } => version.clone(),
            SoftwareTaskDetection::Script { .. } => self.version.clone(),
        };
        match &self.behavior {
            B::Msi(n) | B::Pkg(n) | B::Winget(n) | B::Brew(n) => detection(&n.detect),
            B::Exe(n) => detection(&n.detect),
            B::Bundle(n) => detection(&n.detect),
            B::Dmg(n) => match &n.payload {
                SoftwareTaskDmgPayload::AppCopy { application, .. } => application.version.clone(),
                _ => self.version.clone(),
            },
            B::Msix(n) => n
                .identity
                .version
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("."),
        }
    }
}
