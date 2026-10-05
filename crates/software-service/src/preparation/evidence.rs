//! Software postconditions and association with the server-retained immutable plan.
use rss_mdm_agent_wire::runtime::*;
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
pub fn satisfies(
    observation: &SoftwareDetectionObservation,
    intent: SoftwareTaskIntent,
    version: &str,
) -> bool {
    match (observation, intent) {
        (
            SoftwareDetectionObservation::Present {
                version: observed, ..
            },
            SoftwareTaskIntent::Install | SoftwareTaskIntent::Detect,
        ) => observed == version,
        (SoftwareDetectionObservation::Absent { .. }, SoftwareTaskIntent::Uninstall) => true,
        _ => false,
    }
}
pub fn assess_for(
    result: &SoftwareTaskResult,
    task: &SoftwareTaskSpec,
) -> Result<SoftwareEvidenceAssessment, WireError> {
    assess_execution(result, task.intent, task.definition_digest, &task.steps)
}
pub fn assess_execution(
    result: &SoftwareTaskResult,
    intent: SoftwareTaskIntent,
    definition_digest: [u8; 32],
    steps: &[SoftwareTaskStep],
) -> Result<SoftwareEvidenceAssessment, WireError> {
    use SoftwareEvidenceAssessment as A;
    validate_association(result, intent, definition_digest, steps)?;
    if result
        .steps
        .iter()
        .any(|step| matches!(step.after, SoftwareDetectionObservation::Unknown { .. }))
    {
        return Ok(A::Unknown);
    }
    let reboot = result.steps.iter().any(|step| step.reboot_required);
    let reboot_allowed = result.steps.iter().zip(steps).all(|(result, step)| {
        !result.reboot_required || step.action.reboot == SoftwareTaskReboot::Report
    });
    if reboot {
        return Ok(if reboot_allowed {
            A::RebootPending
        } else {
            A::Unsatisfied
        });
    }
    let matches = result
        .steps
        .iter()
        .zip(steps)
        .enumerate()
        .all(|(index, (result, step))| {
            let intent = if index + 1 == steps.len() {
                intent
            } else {
                SoftwareTaskIntent::Install
            };
            satisfies(&result.after, intent, &detected_version(&step.action))
        });
    Ok(if matches {
        A::Satisfied
    } else {
        A::Unsatisfied
    })
}
fn validate_association(
    result: &SoftwareTaskResult,
    intent: SoftwareTaskIntent,
    definition_digest: [u8; 32],
    steps: &[SoftwareTaskStep],
) -> Result<(), WireError> {
    result.validate()?;
    if result.definition_digest != definition_digest
        || result.intent != intent
        || result.steps.len() != steps.len()
    {
        return Err(WireError::InvalidValue);
    }
    for (result, step) in result.steps.iter().zip(steps) {
        if result.step_digest != step.digest()?
            || result.target != step.target
            || result.package != step.action.package
            || result.identity != observed_identity(&step.action)
        {
            return Err(WireError::InvalidValue);
        }
    }
    Ok(())
}
pub fn observed_identity(action: &SoftwareTaskAction) -> SoftwareObservedIdentity {
    use SoftwareTaskBehavior as B;
    let detection = |v: &SoftwareTaskDetection| match v {
        SoftwareTaskDetection::MsiProduct { product_code, .. } => {
            SoftwareObservedIdentity::MsiProduct {
                product_code: product_code.clone(),
            }
        }
        SoftwareTaskDetection::PkgReceipt { receipt, .. } => SoftwareObservedIdentity::PkgReceipt {
            receipt: receipt.clone(),
        },
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
        SoftwareTaskDetection::Script { command } => SoftwareObservedIdentity::ControlledDetector {
            entry: command.entry.clone(),
        },
    };
    match &action.behavior {
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
pub fn detected_version(action: &SoftwareTaskAction) -> String {
    use SoftwareTaskBehavior as B;
    let detection = |d: &SoftwareTaskDetection| match d {
        SoftwareTaskDetection::MsiProduct { version, .. }
        | SoftwareTaskDetection::PkgReceipt { version, .. }
        | SoftwareTaskDetection::Registry { version, .. }
        | SoftwareTaskDetection::File { version, .. } => version.clone(),
        SoftwareTaskDetection::Script { .. } => action.version.clone(),
    };
    match &action.behavior {
        B::Msi(n) | B::Pkg(n) | B::Winget(n) | B::Brew(n) => detection(&n.detect),
        B::Exe(n) => detection(&n.detect),
        B::Bundle(n) => detection(&n.detect),
        B::Dmg(n) => match &n.payload {
            SoftwareTaskDmgPayload::AppCopy { application, .. } => application.version.clone(),
            _ => action.version.clone(),
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
