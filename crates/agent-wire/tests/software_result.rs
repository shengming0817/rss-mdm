use rss_mdm_agent_wire::*;
use serde_json::json;
#[test]
fn software_result_cannot_claim_a_global_detection_without_step_target_identity() {
    let old = json!({"intent":"install","installerExitCode":0,"detection":"present","definitionDigest":vec![1;32],"observedVersion":"1","evidenceDigest":vec![2;32],"rebootRequired":false,"diagnostics":{"stdout":"","stderr":"","durationMs":1,"executedAt":1,"failure":null}});
    assert!(serde_json::from_value::<SoftwareTaskResult>(old).is_err());
}
fn task() -> SoftwareTaskSpec {
    let id = uuid::Uuid::new_v4();
    let context = SoftwareExecutionContext {
        revision: 1,
        os_version: [10, 0, 22621, 0],
        system_broker: true,
        interactive_user: Some(SoftwareInteractiveUser {
            identity: "S-1-5-21-1-2-3-1001".into(),
            session_id: id,
            administrator: false,
        }),
        source_credentials: vec![],
        msix_sideload: true,
        msix_unsigned: true,
    };
    let invocation = json!({"runAs":"logged_in_user","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let action=serde_json::from_value::<SoftwareTaskAction>(json!({"package":"Acme.Editor","version":"2.0.0.0","reboot":"report","downgrade":"deny","signatures":[],"behavior":{"kind":"msix","container":{"kind":"package","installer":"package"},"identity":{"name":"Acme.Editor","publisher":"CN=Acme","version":[2,0,0,0],"architecture":"x86_64","resourceId":""},"dependencies":[],"deployment":{"kind":"target_user_registration","target":{"kind":"exact","identity":"S-1-5-21-1-2-3-1001"}},"minimumOs":[10,0,19041,0],"requireSideload":true,"allowUnsigned":true,"uninstall":true,"invocation":invocation,"upgrade":"in_place"}})).unwrap();
    let step = SoftwareTaskStep {
        action,
        target: SoftwareExecutionTarget::User {
            identity: "S-1-5-21-1-2-3-1001".into(),
            session_id: id,
        },
        export: SoftwareTaskExport::Direct,
        artifacts: vec![SoftwareTaskArtifact {
            key: "0/package".into(),
            length: 1024,
            sha256: [2; 32],
        }],
    };
    let mut task = SoftwareTaskSpec {
        wire_version: 6,
        tenant_id: id,
        device_id: "device".into(),
        registration_id: id,
        generation: 1,
        task_id: id,
        attempt_id: id,
        permit: TaskPermit::Start,
        expires_at: 200,
        platform: TaskPlatform::Windows,
        architecture: TaskArchitecture::X86_64,
        execution_context: context,
        definition_digest: [0; 32],
        steps: vec![step],
        intent: SoftwareTaskIntent::Install,
        start_mode: SoftwareStartMode::Automatic,
    };
    task.definition_digest = ring::digest::digest(
        &ring::digest::SHA256,
        &serde_json::to_vec(&task.steps).unwrap(),
    )
    .as_ref()
    .try_into()
    .unwrap();
    task.validate().unwrap();
    task
}
fn result(task: &SoftwareTaskSpec) -> SoftwareTaskResult {
    let step = &task.steps[0];
    SoftwareTaskResult {
        intent: task.intent,
        definition_digest: task.definition_digest,
        steps: vec![SoftwareStepResult {
            index: 0,
            step_digest: step.digest().unwrap(),
            target: step.target.clone(),
            package: step.action.package.clone(),
            identity: SoftwareObservedIdentity::MsixRegistration {
                identity: match &step.action.behavior {
                    SoftwareTaskBehavior::Msix(n) => n.identity.clone(),
                    _ => unreachable!(),
                },
            },
            before: SoftwareDetectionObservation::Absent {
                evidence_sha256: [3; 32],
                observed_at: 100,
            },
            after: SoftwareDetectionObservation::Present {
                version: "2.0.0.0".into(),
                evidence_sha256: [4; 32],
                observed_at: 101,
            },
            process: SoftwareProcessObservation::Exited { code: 0 },
            reboot_required: false,
            diagnostics: TaskDiagnostics::new("".into(), "".into(), 1, 100, None).unwrap(),
        }],
    }
}
#[test]
fn another_user_login_package_or_provisioning_receipt_cannot_satisfy_registration() {
    let task = task();
    let good = result(&task);
    good.validate_for(&task).unwrap();
    let mut wrong = good.clone();
    wrong.steps[0].target = SoftwareExecutionTarget::Device;
    assert!(wrong.validate_for(&task).is_err());
    let mut wrong = good.clone();
    if let SoftwareExecutionTarget::User { session_id, .. } = &mut wrong.steps[0].target {
        *session_id = uuid::Uuid::new_v4();
    }
    assert!(wrong.validate_for(&task).is_err());
    let mut wrong = good.clone();
    let SoftwareObservedIdentity::MsixRegistration { identity } = wrong.steps[0].identity.clone()
    else {
        unreachable!()
    };
    wrong.steps[0].identity = SoftwareObservedIdentity::MsixProvisioning { identity };
    assert!(wrong.validate_for(&task).is_err());
    let mut wrong = good.clone();
    wrong.steps[0].step_digest = [9; 32];
    assert!(wrong.validate_for(&task).is_err());
    let mut wrong = good.clone();
    wrong.steps[0].package = "Another.Package".into();
    assert!(wrong.validate_for(&task).is_err());
    let mut wrong = good.clone();
    wrong.steps.clear();
    assert!(wrong.validate_for(&task).is_err());
    let mut wrong = good;
    wrong.steps[0].after = SoftwareDetectionObservation::Present {
        version: "1.0.0.0".into(),
        evidence_sha256: [4; 32],
        observed_at: 101,
    };
    wrong.validate_for(&task).unwrap();
    assert!(!wrong.steps[0].after.satisfies(task.intent, "2.0.0.0"));
}
#[test]
fn a_successful_process_without_independent_material_evidence_is_rejected() {
    let task = task();
    let mut result = result(&task);
    result.steps[0].after = SoftwareDetectionObservation::Present {
        version: "2.0.0.0".into(),
        evidence_sha256: [0; 32],
        observed_at: 101,
    };
    assert!(result.validate_for(&task).is_err());
    result.steps[0].after = SoftwareDetectionObservation::Unknown {
        diagnostic: "query timed out".into(),
    };
    result.validate_for(&task).unwrap();
    assert!(!result.steps[0].after.satisfies(task.intent, "2.0.0.0"));
}
