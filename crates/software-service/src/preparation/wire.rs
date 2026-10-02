//! Sole explicit Resource → executable software wire projection.
use rss_mdm_agent_wire as w;
use rss_mdm_resource as r;

pub(crate) fn software_action(spec: &r::SoftwareSpec) -> w::SoftwareTaskAction {
    w::SoftwareTaskAction {
        package: spec.package.clone(),
        version: spec.version.clone(),
        behavior: map_software_behavior(&spec.behavior),
        signatures: spec.signatures.iter().map(map_software_signature).collect(),
        reboot: map_software_reboot(&spec.reboot),
        downgrade: map_software_downgrade(&spec.downgrade),
        ownership: map_software_ownership(&spec.ownership),
    }
}
fn map_run_as(v: &r::RunAs) -> w::ExecutionIdentity {
    match v {
        r::RunAs::System => w::ExecutionIdentity::System,
        r::RunAs::LoggedInUser => w::ExecutionIdentity::LoggedInUser,
    }
}
fn map_platform(v: &r::Platform) -> w::TaskPlatform {
    match v {
        r::Platform::Windows => w::TaskPlatform::Windows,
        r::Platform::MacOS => w::TaskPlatform::Macos,
    }
}
fn map_architecture(v: &r::Architecture) -> w::TaskArchitecture {
    match v {
        r::Architecture::X86_64 => w::TaskArchitecture::X86_64,
        r::Architecture::Aarch64 => w::TaskArchitecture::Aarch64,
    }
}
fn map_software_scope(input: &r::SoftwareScope) -> w::SoftwareTaskScope {
    match input {
        r::SoftwareScope::System => w::SoftwareTaskScope::System,
        r::SoftwareScope::User => w::SoftwareTaskScope::User,
    }
}
fn map_software_upgrade(input: &r::SoftwareUpgrade) -> w::SoftwareTaskUpgrade {
    match input {
        r::SoftwareUpgrade::InPlace => w::SoftwareTaskUpgrade::InPlace,
        r::SoftwareUpgrade::UninstallThenInstall => w::SoftwareTaskUpgrade::UninstallThenInstall,
        r::SoftwareUpgrade::Deny => w::SoftwareTaskUpgrade::Deny,
    }
}
fn map_exit_code_policy(input: &r::ExitCodePolicy) -> w::SoftwareTaskExitCodes {
    w::SoftwareTaskExitCodes {
        success: input.success.clone(),
        reboot: input.reboot.clone(),
    }
}
fn map_native_invocation(input: &r::NativeInvocation) -> w::SoftwareTaskInvocation {
    w::SoftwareTaskInvocation {
        run_as: map_run_as(&input.run_as),
        arguments: input.arguments.clone(),
        environment: input.environment.clone(),
        timeout_seconds: input.timeout_seconds,
        output_bytes: input.output_bytes,
        exit_codes: map_exit_code_policy(&input.exit_codes),
    }
}
fn map_software_interpreter(input: &r::SoftwareInterpreter) -> w::SoftwareTaskInterpreter {
    match input {
        r::SoftwareInterpreter::PowerShell7 => w::SoftwareTaskInterpreter::PowerShell7,
        r::SoftwareInterpreter::PosixSh => w::SoftwareTaskInterpreter::PosixSh,
        r::SoftwareInterpreter::Bash => w::SoftwareTaskInterpreter::Bash,
    }
}
fn map_software_script(input: &r::SoftwareScript) -> w::SoftwareTaskScript {
    w::SoftwareTaskScript {
        interpreter: map_software_interpreter(&input.interpreter),
        entry: input.entry.clone(),
        invocation: map_native_invocation(&input.invocation),
    }
}
fn map_native_removal(input: &r::NativeRemoval) -> w::SoftwareTaskRemoval {
    w::SoftwareTaskRemoval {
        installer: input.installer.clone(),
        invocation: map_native_invocation(&input.invocation),
    }
}
fn map_native_software(input: &r::NativeSoftware) -> w::SoftwareTaskNative {
    w::SoftwareTaskNative {
        installer: input.installer.clone(),
        scope: map_software_scope(&input.scope),
        install: map_native_invocation(&input.install),
        upgrade_invocation: map_native_invocation(&input.upgrade_invocation),
        upgrade: map_software_upgrade(&input.upgrade),
        uninstall: input.uninstall.as_ref().map(map_native_removal),
        detect: map_software_detection(&input.detect),
    }
}
fn map_exe_software(input: &r::ExeSoftware) -> w::SoftwareTaskExe {
    w::SoftwareTaskExe {
        installer: input.installer.clone(),
        scope: map_software_scope(&input.scope),
        install: map_native_invocation(&input.install),
        upgrade_invocation: map_native_invocation(&input.upgrade_invocation),
        upgrade: map_software_upgrade(&input.upgrade),
        uninstall: input.uninstall.as_ref().map(map_native_removal),
        layout: input.layout.clone(),
        detect: map_software_detection(&input.detect),
    }
}
fn map_bundle_software(input: &r::BundleSoftware) -> w::SoftwareTaskBundleBehavior {
    w::SoftwareTaskBundleBehavior {
        archive: input.archive.clone(),
        manifest: map_bundle_manifest(&input.manifest),
        install: map_software_script(&input.install),
        uninstall: input.uninstall.as_ref().map(map_software_script),
        detect: map_software_detection(&input.detect),
    }
}
fn map_mac_application(input: &r::MacApplication) -> w::SoftwareTaskMacApplication {
    w::SoftwareTaskMacApplication {
        path: input.path.clone(),
        bundle_id: input.bundle_id.clone(),
        version: input.version.clone(),
        material_sha256: input.material_sha256,
        target_name: input.target_name.clone(),
    }
}
fn map_dmg_payload(input: &r::DmgPayload) -> w::SoftwareTaskDmgPayload {
    match input {
        r::DmgPayload::AppCopy {
            application,
            uninstall,
        } => w::SoftwareTaskDmgPayload::AppCopy {
            application: map_mac_application(application),
            uninstall: *uninstall,
        },
        r::DmgPayload::ContainedPkg {
            path,
            length,
            sha256,
            receipt,
            uninstall,
        } => w::SoftwareTaskDmgPayload::ContainedPkg {
            path: path.clone(),
            length: *length,
            sha256: *sha256,
            receipt: receipt.clone(),
            uninstall: uninstall.as_ref().map(map_native_removal),
        },
    }
}
fn map_dmg_software(input: &r::DmgSoftware) -> w::SoftwareTaskDmg {
    w::SoftwareTaskDmg {
        image: input.image.clone(),
        volume: input.volume.clone(),
        scope: map_software_scope(&input.scope),
        invocation: map_native_invocation(&input.invocation),
        upgrade: map_software_upgrade(&input.upgrade),
        payload: map_dmg_payload(&input.payload),
    }
}
fn map_msix_identity(input: &r::MsixIdentity) -> w::SoftwareTaskMsixIdentity {
    w::SoftwareTaskMsixIdentity {
        name: input.name.clone(),
        publisher: input.publisher.clone(),
        version: input.version,
        architecture: match input.architecture {
            r::MsixArchitecture::X86_64 => w::SoftwareTaskMsixArchitecture::X86_64,
            r::MsixArchitecture::Aarch64 => w::SoftwareTaskMsixArchitecture::Aarch64,
            r::MsixArchitecture::Neutral => w::SoftwareTaskMsixArchitecture::Neutral,
        },
        resource_id: input.resource_id.clone(),
    }
}
fn map_msix_member(input: &r::MsixMember) -> w::SoftwareTaskMsixMember {
    w::SoftwareTaskMsixMember {
        path: input.path.clone(),
        identity: map_msix_identity(&input.identity),
        length: input.length,
        sha256: input.sha256,
    }
}
fn map_msix_container(input: &r::MsixContainer) -> w::SoftwareTaskMsixContainer {
    match input {
        r::MsixContainer::Package { installer } => w::SoftwareTaskMsixContainer::Package {
            installer: installer.clone(),
        },
        r::MsixContainer::Bundle { installer, members } => w::SoftwareTaskMsixContainer::Bundle {
            installer: installer.clone(),
            members: members.iter().map(map_msix_member).collect(),
        },
    }
}
fn map_software_user(input: &r::SoftwareUser) -> w::SoftwareTaskUser {
    match input {
        r::SoftwareUser::ActiveInteractive => w::SoftwareTaskUser::ActiveInteractive,
        r::SoftwareUser::Exact { identity } => w::SoftwareTaskUser::Exact {
            identity: identity.clone(),
        },
    }
}
fn map_msix_deployment(input: &r::MsixDeployment) -> w::SoftwareTaskMsixDeployment {
    match input {
        r::MsixDeployment::TargetUserRegistration { target } => {
            w::SoftwareTaskMsixDeployment::TargetUserRegistration {
                target: map_software_user(target),
            }
        }
        r::MsixDeployment::DeviceProvisioning => w::SoftwareTaskMsixDeployment::DeviceProvisioning,
    }
}
fn map_msix_software(input: &r::MsixSoftware) -> w::SoftwareTaskMsix {
    w::SoftwareTaskMsix {
        container: map_msix_container(&input.container),
        identity: map_msix_identity(&input.identity),
        dependencies: input.dependencies.iter().map(map_msix_identity).collect(),
        deployment: map_msix_deployment(&input.deployment),
        minimum_os: input.minimum_os,
        require_sideload: input.require_sideload,
        allow_unsigned: input.allow_unsigned,
        uninstall: input.uninstall,
        invocation: map_native_invocation(&input.invocation),
        upgrade: map_software_upgrade(&input.upgrade),
    }
}
fn map_software_detection(input: &r::SoftwareDetection) -> w::SoftwareTaskDetection {
    match input {
        r::SoftwareDetection::MsiProduct {
            product_code,
            version,
        } => w::SoftwareTaskDetection::MsiProduct {
            product_code: product_code.clone(),
            version: version.clone(),
        },
        r::SoftwareDetection::PkgReceipt { receipt, version } => {
            w::SoftwareTaskDetection::PkgReceipt {
                receipt: receipt.clone(),
                version: version.clone(),
            }
        }
        r::SoftwareDetection::Registry {
            scope,
            key,
            value,
            version,
        } => w::SoftwareTaskDetection::Registry {
            scope: map_software_scope(scope),
            key: key.clone(),
            value: value.clone(),
            version: version.clone(),
        },
        r::SoftwareDetection::File {
            scope,
            path,
            version,
            sha256,
        } => w::SoftwareTaskDetection::File {
            scope: map_software_scope(scope),
            path: path.clone(),
            version: version.clone(),
            sha256: *sha256,
        },
        r::SoftwareDetection::Script { command } => w::SoftwareTaskDetection::Script {
            command: map_software_script(command),
        },
    }
}
fn map_software_behavior(input: &r::SoftwareBehavior) -> w::SoftwareTaskBehavior {
    match input {
        r::SoftwareBehavior::Msi(value) => w::SoftwareTaskBehavior::Msi(map_native_software(value)),
        r::SoftwareBehavior::Pkg(value) => w::SoftwareTaskBehavior::Pkg(map_native_software(value)),
        r::SoftwareBehavior::Bundle(value) => {
            w::SoftwareTaskBehavior::Bundle(map_bundle_software(value))
        }
        r::SoftwareBehavior::Winget(value) => {
            w::SoftwareTaskBehavior::Winget(map_native_software(value))
        }
        r::SoftwareBehavior::Brew(value) => {
            w::SoftwareTaskBehavior::Brew(map_native_software(value))
        }
        r::SoftwareBehavior::Exe(value) => w::SoftwareTaskBehavior::Exe(map_exe_software(value)),
        r::SoftwareBehavior::Dmg(value) => w::SoftwareTaskBehavior::Dmg(map_dmg_software(value)),
        r::SoftwareBehavior::Msix(value) => w::SoftwareTaskBehavior::Msix(map_msix_software(value)),
    }
}
fn map_software_signature(input: &r::SoftwareSignature) -> w::SoftwareTaskSignature {
    w::SoftwareTaskSignature {
        artifact: input.artifact.clone(),
        mechanism: map_signature_mechanism(&input.mechanism),
        publisher: input.publisher.clone(),
    }
}
fn map_signature_mechanism(input: &r::SignatureMechanism) -> w::SoftwareTaskSignatureMechanism {
    match input {
        r::SignatureMechanism::Authenticode => w::SoftwareTaskSignatureMechanism::Authenticode,
        r::SignatureMechanism::AppleDeveloperId => {
            w::SoftwareTaskSignatureMechanism::AppleDeveloperId
        }
        r::SignatureMechanism::Msix => w::SoftwareTaskSignatureMechanism::Msix,
    }
}
fn map_bundle_entry(input: &r::BundleEntry) -> w::SoftwareTaskBundleEntry {
    w::SoftwareTaskBundleEntry {
        length: input.length,
        sha256: input.sha256,
    }
}
fn map_bundle_manifest(input: &r::BundleManifest) -> w::SoftwareTaskBundle {
    w::SoftwareTaskBundle {
        schema: input.schema,
        platform: map_platform(&input.platform),
        architecture: map_architecture(&input.architecture),
        entries: input
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), map_bundle_entry(v)))
            .collect(),
    }
}
fn map_software_reboot(input: &r::SoftwareReboot) -> w::SoftwareTaskReboot {
    match input {
        r::SoftwareReboot::Forbid => w::SoftwareTaskReboot::Forbid,
        r::SoftwareReboot::Report => w::SoftwareTaskReboot::Report,
    }
}
fn map_software_downgrade(input: &r::SoftwareDowngrade) -> w::SoftwareTaskDowngrade {
    match input {
        r::SoftwareDowngrade::Deny => w::SoftwareTaskDowngrade::Deny,
        r::SoftwareDowngrade::Allow => w::SoftwareTaskDowngrade::Allow,
    }
}
fn map_software_ownership(input: &r::SoftwareOwnership) -> w::SoftwareTaskOwnership {
    match input {
        r::SoftwareOwnership::ManagedOnly => w::SoftwareTaskOwnership::ManagedOnly,
        r::SoftwareOwnership::AllowUserExisting => w::SoftwareTaskOwnership::AllowUserExisting,
    }
}

pub(crate) fn software_step(
    input: &r::SoftwareSpec,
    index: usize,
    platform: w::TaskPlatform,
    context: &w::SoftwareExecutionContext,
    export: w::SoftwareTaskExport,
) -> std::result::Result<w::SoftwareTaskStep, w::WireError> {
    let mut action = software_action(input);
    let target = action.bind_execution_target(platform, context)?;
    let artifacts = input
        .artifacts
        .iter()
        .map(|(key, artifact)| w::SoftwareTaskArtifact {
            key: format!("{index}/{key}"),
            length: artifact.length,
            sha256: artifact.sha256,
        })
        .collect();
    Ok(w::SoftwareTaskStep {
        action,
        artifacts,
        target,
        export,
    })
}
