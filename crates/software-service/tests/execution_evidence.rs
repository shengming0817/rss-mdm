use rss_mdm_agent_wire::runtime::*;
use rss_mdm_software_service::preparation::evidence::*;
use serde_json::json;
use sha2::Digest;
fn task() -> SoftwareTaskSpec {
    let id = uuid::Uuid::new_v4();
    let context = SoftwareExecutionContext {
        revision: 1,
        os_version: [10, 0, 22621, 0],
        user_helper: true,
        system_broker: true,
        interactive_user: Some(SoftwareInteractiveUser {
            windows_authority: None,
            generated_uid: None,
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
        step_id: SoftwareStepDefinition {
            resource: "test".into(),
            version: "1".into(),
            variant: "default".into(),
            digest: [1; 32],
        }
        .step_id()
        .unwrap(),
        definition: SoftwareStepDefinition {
            resource: "test".into(),
            version: "1".into(),
            variant: "default".into(),
            digest: [1; 32],
        },
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
        wire_version: 1,
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
        authorization: TaskAuthorization::Policy {
            policy_id: uuid::Uuid::new_v4(),
            policy_version: uuid::Uuid::new_v4(),
        },
        execution_context: context,
        definition_digest: [0; 32],
        steps: vec![step],
        intent: SoftwareTaskIntent::Install,
        start_mode: SoftwareStartMode::Automatic,
    };
    task.definition_digest = sha2::Sha256::digest(serde_json::to_vec(&task.steps).unwrap()).into();
    task.validate().unwrap();
    task
}
fn result(task: &SoftwareTaskSpec) -> SoftwareTaskResult {
    let step = &task.steps[0];
    SoftwareTaskResult {
        intent: task.intent,
        definition_digest: task.definition_digest,
        steps: vec![SoftwareStepResult {
            step_id: step.step_id,
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
    assess_for(&good, &task).unwrap();
    let mut wrong = good.clone();
    wrong.steps[0].target = SoftwareExecutionTarget::Device;
    assert!(assess_for(&wrong, &task).is_err());
    let mut wrong = good.clone();
    if let SoftwareExecutionTarget::User { session_id, .. } = &mut wrong.steps[0].target {
        *session_id = uuid::Uuid::new_v4();
    }
    assert!(assess_for(&wrong, &task).is_err());
    let mut wrong = good.clone();
    let SoftwareObservedIdentity::MsixRegistration { identity } = wrong.steps[0].identity.clone()
    else {
        unreachable!()
    };
    wrong.steps[0].identity = SoftwareObservedIdentity::MsixProvisioning { identity };
    assert!(assess_for(&wrong, &task).is_err());
    let mut wrong = good.clone();
    wrong.steps[0].step_id = [9; 32];
    assert!(assess_for(&wrong, &task).is_err());
    let mut wrong = good.clone();
    wrong.steps[0].step_digest = [9; 32];
    assert!(assess_for(&wrong, &task).is_err());
    let mut wrong = good.clone();
    wrong.steps[0].package = "Another.Package".into();
    assert!(assess_for(&wrong, &task).is_err());
    let mut wrong = good.clone();
    wrong.steps.clear();
    assert!(assess_for(&wrong, &task).is_err());
    let mut wrong = good;
    wrong.steps[0].after = SoftwareDetectionObservation::Present {
        version: "1.0.0.0".into(),
        evidence_sha256: [4; 32],
        observed_at: 101,
    };
    assess_for(&wrong, &task).unwrap();
    assert!(!satisfies(&wrong.steps[0].after, task.intent, "2.0.0.0"));
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
    assert!(assess_for(&result, &task).is_err());
    result.steps[0].after = SoftwareDetectionObservation::Unknown {
        diagnostic: "query timed out".into(),
    };
    assess_for(&result, &task).unwrap();
    assert!(!satisfies(&result.steps[0].after, task.intent, "2.0.0.0"));
}

#[test]
fn assessment_uses_detection_and_keeps_reboot_and_unknown_distinct() {
    use SoftwareEvidenceAssessment as A;
    let mut task = task();
    let mut evidence = result(&task);
    evidence.steps[0].process = SoftwareProcessObservation::NotRun;
    assert_eq!(assess_for(&evidence, &task).unwrap(), A::Satisfied);
    evidence.steps[0].after = SoftwareDetectionObservation::Absent {
        evidence_sha256: [4; 32],
        observed_at: 101,
    };
    assert_eq!(assess_for(&evidence, &task).unwrap(), A::Unsatisfied);
    evidence.steps[0].reboot_required = true;
    assert_eq!(assess_for(&evidence, &task).unwrap(), A::RebootPending);
    task.steps[0].action.reboot = SoftwareTaskReboot::Forbid;
    evidence.steps[0].step_digest = task.steps[0].digest().unwrap();
    assert_eq!(assess_for(&evidence, &task).unwrap(), A::Unsatisfied);
    evidence.steps[0].after = SoftwareDetectionObservation::Unknown {
        diagnostic: "native detection unavailable".into(),
    };
    assert_eq!(assess_for(&evidence, &task).unwrap(), A::Unknown);
}
#[test]
fn root_uninstall_requires_absence_while_dependencies_require_exact_installation() {
    use SoftwareEvidenceAssessment as A;
    let mut task = task();
    task.intent = SoftwareTaskIntent::Uninstall;
    let mut dependency = task.steps[0].clone();
    dependency.action.package = "Acme.Dependency".into();
    dependency.definition.resource = "dependency".into();
    dependency.step_id = dependency.definition.step_id().unwrap();
    task.steps.insert(0, dependency);
    let mut evidence = result(&task);
    evidence.steps.push(evidence.steps[0].clone());
    let step = &task.steps[1];
    evidence.steps[1].index = 1;
    evidence.steps[1].step_id = step.step_id;
    evidence.steps[1].step_digest = step.digest().unwrap();
    evidence.steps[1].package = step.action.package.clone();
    evidence.steps[1].after = SoftwareDetectionObservation::Absent {
        evidence_sha256: [4; 32],
        observed_at: 101,
    };
    assert_eq!(assess_for(&evidence, &task).unwrap(), A::Satisfied);
    evidence.steps[0].after = SoftwareDetectionObservation::Absent {
        evidence_sha256: [4; 32],
        observed_at: 101,
    };
    assert_eq!(assess_for(&evidence, &task).unwrap(), A::Unsatisfied);
    evidence.steps[0].after = SoftwareDetectionObservation::Present {
        version: "1.0.0.0".into(),
        evidence_sha256: [4; 32],
        observed_at: 101,
    };
    assert_eq!(assess_for(&evidence, &task).unwrap(), A::Unsatisfied);
}
