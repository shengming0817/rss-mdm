//! Software execution eligibility over protocol values; never creates execution authority.
use rss_mdm_agent_wire::runtime::*;
/// Check product execution eligibility and select the concrete current target.
pub fn action_target(
    action: &SoftwareTaskAction,
    platform: TaskPlatform,
    context: &SoftwareExecutionContext,
) -> Result<SoftwareExecutionTarget, WireError> {
    context.validate_for(platform)?;
    if action.required_profile(platform).is_none() {
        return Err(WireError::InvalidValue);
    }
    use SoftwareTaskBehavior as B;
    let invocation = action.behavior.invocation();
    if matches!(invocation.run_as, ExecutionIdentity::System) && !context.system_broker {
        return Err(WireError::InvalidValue);
    }
    if matches!(&action.behavior, B::Brew(_))
        && context
            .interactive_user
            .as_ref()
            .is_none_or(|u| u.identity.parse::<u32>().ok().is_none_or(|uid| uid == 0))
    {
        return Err(WireError::InvalidValue);
    }
    let needs_user = invocation.run_as == ExecutionIdentity::LoggedInUser;
    if needs_user && !context.user_helper {
        return Err(WireError::InvalidValue);
    }
    let target = if needs_user {
        let user = context
            .interactive_user
            .as_ref()
            .ok_or(WireError::InvalidValue)?;
        SoftwareExecutionTarget::User {
            identity: user.identity.clone(),
            session_id: user.session_id,
        }
    } else {
        SoftwareExecutionTarget::Device
    };
    if matches!(&action.behavior,B::Winget(n) if n.install.run_as==ExecutionIdentity::System)
        && !context
            .interactive_user
            .as_ref()
            .is_some_and(|u| u.administrator)
    {
        return Err(WireError::InvalidValue);
    }
    let detector = match &action.behavior {
        B::Msi(n) | B::Pkg(n) | B::Winget(n) | B::Brew(n) => Some(&n.detect),
        B::Exe(n) => Some(&n.detect),
        B::Bundle(n) => Some(&n.detect),
        _ => None,
    };
    if let Some(SoftwareTaskDetection::Script { command }) = detector {
        match command.invocation.run_as {
            ExecutionIdentity::System if !context.system_broker => {
                return Err(WireError::InvalidValue);
            }
            ExecutionIdentity::LoggedInUser
                if context.interactive_user.is_none() || !context.user_helper =>
            {
                return Err(WireError::InvalidValue);
            }
            _ => (),
        }
    }
    if let B::Msix(n) = &action.behavior {
        if context.os_version < n.minimum_os
            || (n.require_sideload && !context.msix_sideload)
            || (n.allow_unsigned && !context.msix_unsigned)
        {
            return Err(WireError::InvalidValue);
        }
        match &n.deployment {
            SoftwareTaskMsixDeployment::TargetUserRegistration { target: selector } => {
                let user = context
                    .interactive_user
                    .as_ref()
                    .ok_or(WireError::InvalidValue)?;
                if matches!(selector,SoftwareTaskUser::Exact{identity} if identity!=&user.identity)
                    || !needs_user
                {
                    return Err(WireError::InvalidValue);
                }
            }
            SoftwareTaskMsixDeployment::DeviceProvisioning if needs_user => {
                return Err(WireError::InvalidValue);
            }
            _ => (),
        }
    }
    Ok(target)
}
/// Freeze an approved interactive selector to the current account and login.
pub fn bind_target(
    action: &mut SoftwareTaskAction,
    platform: TaskPlatform,
    context: &SoftwareExecutionContext,
) -> Result<SoftwareExecutionTarget, WireError> {
    let target = action_target(action, platform, context)?;
    if let (SoftwareTaskBehavior::Msix(n), SoftwareExecutionTarget::User { identity, .. }) =
        (&mut action.behavior, &target)
        && let SoftwareTaskMsixDeployment::TargetUserRegistration { target } = &mut n.deployment
    {
        *target = SoftwareTaskUser::Exact {
            identity: identity.clone(),
        };
    }
    Ok(target)
}
/// Read the root native operation's declared process identity.
pub fn execution_identity(action: &SoftwareTaskAction) -> ExecutionIdentity {
    action.behavior.invocation().run_as
}
/// Check current broker/helper availability for a script process identity.
pub fn identity_target(
    identity: ExecutionIdentity,
    platform: TaskPlatform,
    context: &SoftwareExecutionContext,
) -> Result<SoftwareExecutionTarget, WireError> {
    context.validate_for(platform)?;
    match identity {
        ExecutionIdentity::System if context.system_broker => Ok(SoftwareExecutionTarget::Device),
        ExecutionIdentity::LoggedInUser if context.user_helper => {
            let user = context
                .interactive_user
                .as_ref()
                .ok_or(WireError::InvalidValue)?;
            Ok(SoftwareExecutionTarget::User {
                identity: user.identity.clone(),
                session_id: user.session_id,
            })
        }
        _ => Err(WireError::InvalidValue),
    }
}
/// Require the exact source-scoped read credential to exist in the current context.
pub fn validate_export_context(
    export: &SoftwareTaskExport,
    context: &SoftwareExecutionContext,
) -> Result<(), WireError> {
    if let SoftwareTaskExport::Brew {
        binding,
        credential_reference,
        ..
    } = export
        && !context
            .source_credentials
            .iter()
            .any(|c| c.source == binding.target && c.reference == *credential_reference)
    {
        return Err(WireError::InvalidValue);
    }
    Ok(())
}
/// Recheck every frozen software step before issuing Offer or Start authority.
pub fn validate_task_admission(task: &SoftwareTaskSpec) -> Result<(), WireError> {
    for step in &task.steps {
        if action_target(&step.action, task.platform, &task.execution_context)? != step.target {
            return Err(WireError::InvalidValue);
        }
        validate_export_context(&step.export, &task.execution_context)?;
    }
    Ok(())
}
