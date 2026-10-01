//! Current locally reported execution context, distinct from capabilities and scope.
use crate::{
    ExecutionIdentity, SoftwareTaskAction, SoftwareTaskBehavior, SoftwareTaskDetection,
    SoftwareTaskMsixDeployment, SoftwareTaskUser, TaskPlatform, WireError,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Complete current native execution environment reported by this registration.
pub struct SoftwareExecutionContext {
    /// Strictly increasing local context generation; retries retain the same value.
    pub revision: u64,
    /// Current native Windows sideload policy.
    pub msix_sideload: bool,
    /// Current native API support for explicitly approved unsigned packages.
    pub msix_unsigned: bool,
    /// Complete numeric OS version, not an inferred product/platform string.
    pub os_version: [u16; 4],
    /// Whether the native system broker is available in this Agent installation.
    pub system_broker: bool,
    /// Exact live interactive session, when one exists.
    #[serde(deserialize_with = "super::required_option")]
    pub interactive_user: Option<SoftwareInteractiveUser>,
    /// Source-scoped read credential references actually available locally.
    pub source_credentials: Vec<SoftwareReadCredential>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// One concrete live OS session.
pub struct SoftwareInteractiveUser {
    /// Windows SID or macOS numeric UID.
    pub identity: String,
    /// Changes on logoff/login; identical account names cannot reuse a previous session.
    #[serde(with = "crate::strict_uuid")]
    pub session_id: Uuid,
    /// Privilege needed by the exact native profile, not a generic authorization grant.
    pub administrator: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Availability of a particular source read credential in the local Agent.
pub struct SoftwareReadCredential {
    /// Exact source identity in the consuming tenant.
    pub source: String,
    /// Host-provisioned opaque credential reference; never token bytes or a URL.
    pub reference: String,
}
impl SoftwareExecutionContext {
    /// Validate the exact OS identity rather than accepting account labels.
    pub fn validate_for(&self, platform: TaskPlatform) -> Result<(), WireError> {
        self.validate()?;
        if let Some(u) = &self.interactive_user {
            let valid = match platform {
                TaskPlatform::Windows => u.identity.strip_prefix("S-1-").is_some_and(|tail| {
                    tail.split('-').count() >= 2
                        && tail
                            .split('-')
                            .all(|n| !n.is_empty() && n.parse::<u32>().is_ok())
                }),
                TaskPlatform::Macos => {
                    u.identity.parse::<u32>().is_ok()
                        && u.identity.bytes().all(|b| b.is_ascii_digit())
                }
            };
            if !valid {
                return Err(WireError::InvalidValue);
            }
        }
        if platform == TaskPlatform::Macos && (self.msix_sideload || self.msix_unsigned) {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
    /// An operation retry retains its context; a change uses a newer generation.
    pub fn validate_update(&self, previous: &Self) -> Result<(), WireError> {
        self.validate()?;
        if self.revision < previous.revision
            || (self.revision == previous.revision && self != previous)
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
    /// Bound structural validation for every context update.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.revision == 0
            || self.revision > i64::MAX as u64
            || self.os_version == [0; 4]
            || self.source_credentials.len() > 16
        {
            return Err(WireError::InvalidValue);
        }
        let valid = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
        };
        if self
            .interactive_user
            .as_ref()
            .is_some_and(|u| !valid(&u.identity, 184) || u.session_id.is_nil())
        {
            return Err(WireError::InvalidValue);
        }
        let mut seen = std::collections::BTreeSet::new();
        for c in &self.source_credentials {
            if !valid(&c.source, 128)
                || !valid(&c.reference, 128)
                || !seen.insert((&c.source, &c.reference))
            {
                return Err(WireError::InvalidValue);
            }
        }
        Ok(())
    }
}

/// Concrete effect target bound before an Offer is signed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SoftwareExecutionTarget {
    /// Device installation or provisioning; user registration is a different target.
    Device,
    /// One exact live interactive OS account and login generation.
    User {
        /// Exact SID/UID.
        identity: String,
        /// Exact login generation.
        #[serde(with = "crate::strict_uuid")]
        session_id: Uuid,
    },
}
impl SoftwareTaskAction {
    /// Shared prerequisites for every step at preview, queue, Offer and Start.
    pub fn execution_target(
        &self,
        platform: TaskPlatform,
        context: &SoftwareExecutionContext,
    ) -> Result<SoftwareExecutionTarget, WireError> {
        context.validate_for(platform)?;
        if self.required_profile(platform).is_none() {
            return Err(WireError::InvalidValue);
        }
        use SoftwareTaskBehavior as B;
        let invocation = match &self.behavior {
            B::Msi(n) | B::Pkg(n) | B::Winget(n) | B::Brew(n) => &n.install,
            B::Exe(n) => &n.install,
            B::Bundle(n) => &n.install.invocation,
            B::Dmg(n) => &n.invocation,
            B::Msix(n) => &n.invocation,
        };
        if matches!(invocation.run_as, ExecutionIdentity::System) && !context.system_broker {
            return Err(WireError::InvalidValue);
        }
        if matches!(&self.behavior, B::Brew(_))
            && context
                .interactive_user
                .as_ref()
                .is_none_or(|u| u.identity.parse::<u32>().ok().is_none_or(|uid| uid == 0))
        {
            return Err(WireError::InvalidValue);
        }
        let needs_user = invocation.run_as == ExecutionIdentity::LoggedInUser;
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
        if matches!(&self.behavior,B::Winget(n) if n.install.run_as==ExecutionIdentity::System)
            && !context
                .interactive_user
                .as_ref()
                .is_some_and(|u| u.administrator)
        {
            return Err(WireError::InvalidValue);
        }
        let detector = match &self.behavior {
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
                ExecutionIdentity::LoggedInUser if context.interactive_user.is_none() => {
                    return Err(WireError::InvalidValue);
                }
                _ => (),
            }
        }
        if let B::Msix(n) = &self.behavior {
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
    /// Resolve active-user selection into the concrete task-local account.
    pub fn bind_execution_target(
        &mut self,
        platform: TaskPlatform,
        context: &SoftwareExecutionContext,
    ) -> Result<SoftwareExecutionTarget, WireError> {
        let target = self.execution_target(platform, context)?;
        if let (SoftwareTaskBehavior::Msix(n), SoftwareExecutionTarget::User { identity, .. }) =
            (&mut self.behavior, &target)
            && let SoftwareTaskMsixDeployment::TargetUserRegistration { target } = &mut n.deployment
        {
            *target = SoftwareTaskUser::Exact {
                identity: identity.clone(),
            };
        }
        Ok(target)
    }
}
