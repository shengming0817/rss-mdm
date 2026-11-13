use crate::control::Error;
use rss_device_command::StateDigest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Common execution envelope carries target identity, never client-asserted OS or authorization facts.
#[derive(
    schemars::JsonSchema, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeTarget {
    Device,
    EnrolledUser,
    User { user_id: String },
}
impl NativeTarget {
    pub(crate) fn matches_windows_context(&self, enrolled_user: bool) -> bool {
        match self {
            Self::Device => true,
            Self::EnrolledUser => enrolled_user,
            Self::User { .. } => false,
        }
    }
    pub fn user_key(&self) -> &str {
        match self {
            Self::Device => "",
            Self::EnrolledUser => "enrolled_user",
            Self::User { user_id } => user_id,
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        if let Self::User { user_id } = self
            && (user_id.trim().is_empty()
                || user_id.len() > 256
                || user_id.chars().any(char::is_control))
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum Task {
    Windows {
        request: rss_mdm_windows_mdm::native::Execution,
    },
    Macos {
        request: rss_mdm_apple_mdm::native::request::Request,
    },
}
impl Task {
    pub fn purpose(&self) -> Result<rss_mdm_registration_service::Purpose, Error> {
        use rss_mdm_registration_service::Purpose;
        Ok(match self {
            Self::Windows {
                request: rss_mdm_windows_mdm::native::Execution::SyncMl { request },
            } if request
                .requires_linked_enrollment()
                .map_err(|_| Error::Malformed)? =>
            {
                Purpose::WindowsDeclared
            }
            _ => Purpose::Primary,
        })
    }
    pub fn source(&self) -> rss_mdm_inventory::ReportSource {
        match self {
            Self::Windows { .. } => rss_mdm_inventory::ReportSource::MdmWindows,
            Self::Macos { .. } => rss_mdm_inventory::ReportSource::MdmApple,
        }
    }
    pub fn permissions(&self) -> Result<Vec<crate::control::authorization::Permission>, Error> {
        use rss_mdm_authorization_service::native::{self, Request};
        native::required(match self {
            Self::Windows { request } => Request::Windows(request),
            Self::Macos { request } => Request::Macos(request),
        })
        .map_err(|e| match e {
            native::Error::Malformed => Error::Malformed,
            native::Error::Unsupported => Error::Unsupported,
        })
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub operation_id: Uuid,
    pub input_version: String,
    pub target: NativeTarget,
    pub task: Task,
    pub deadline: i64,
}
impl Create {
    pub fn profile_target(&self) -> Option<(&str, Uuid, bool)> {
        use rss_mdm_apple_mdm::native::request::Request as A;
        match &self.task {
            Task::Macos {
                request: A::InstallProfile { profile },
            } => Some((&profile.identifier, profile.uuid, true)),
            Task::Macos {
                request: A::RemoveProfile { identifier, uuid },
            } => Some((identifier, *uuid, false)),
            _ => None,
        }
    }
    pub fn digest(
        &self,
        protector: &rss_mdm_native_protection::Protector,
        tenant: rss_request_context::TenantId,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<StateDigest, Error> {
        let digest = crate::control::protection::fingerprint(
            protector,
            tenant,
            device,
            "native-input/v1",
            &(&self.input_version, &self.target, &self.task),
        )?;
        Ok(StateDigest::from_bytes(
            digest.try_into().map_err(|_| Error::Malformed)?,
        ))
    }
    pub fn validate(&self, now: i64) -> Result<(), Error> {
        if self.operation_id.is_nil()
            || self.deadline <= now
            || self.deadline.checked_mul(1_000_000).is_none()
            || self.input_version.is_empty()
            || self.input_version.len() > 128
            || self.input_version.chars().any(char::is_control)
        {
            return Err(Error::Malformed);
        }
        self.target.validate()?;
        if matches!(
            (&self.task, &self.target),
            (Task::Macos { .. }, NativeTarget::EnrolledUser)
                | (Task::Windows { .. }, NativeTarget::User { .. })
        ) {
            return Err(Error::Malformed);
        }
        if matches!(self.task, Task::Macos { .. })
            && let NativeTarget::User { user_id } = &self.target
        {
            let id = Uuid::parse_str(user_id).map_err(|_| Error::Malformed)?;
            if id.is_nil() || id.to_string() != *user_id {
                return Err(Error::Malformed);
            }
        }
        if let Some((identifier, uuid, _)) = self.profile_target()
            && (uuid.is_nil()
                || identifier.is_empty()
                || identifier.len() > 1024
                || identifier.chars().any(char::is_control))
        {
            return Err(Error::Malformed);
        }
        if let Task::Windows {
            request: rss_mdm_windows_mdm::native::Execution::SyncMl { request },
        } = &self.task
        {
            for object in request.objects().map_err(|_| Error::Malformed)? {
                if (object.scope() == rss_mdm_windows_mdm::native::Scope::User)
                    != matches!(self.target, NativeTarget::EnrolledUser)
                {
                    return Err(Error::Malformed);
                }
            }
        }
        self.task.permissions()?;
        if serde_json::to_vec(self)
            .map_err(|_| Error::Malformed)?
            .len()
            > 16 * 1024 * 1024
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchV1 {
    pub device: rss_mdm_agent_wire::DeviceId,
    pub operation_id: Uuid,
    pub generation: i64,
    pub epoch: i64,
}
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub request_id: Uuid,
    pub expected_revision: i64,
}

/// Native exchange phases; database values are decoded fail-closed.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptPhase {
    Prepare,
    Execute,
    Observe,
}
impl AttemptPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Execute => "execute",
            Self::Observe => "observe",
        }
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "prepare" => Ok(Self::Prepare),
            "execute" => Ok(Self::Execute),
            "observe" => Ok(Self::Observe),
            _ => Err(Error::Unavailable(
                crate::control::Failure::CommandInvariant,
            )),
        }
    }
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaskSummary {
    pub platform: rss_mdm_agent_wire::runtime::TaskPlatform,
    pub kind: TaskKind,
    pub name: String,
    pub objects: Vec<String>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    SyncMl,
    Msi,
    Command,
    InstallProfile,
    RemoveProfile,
    Declarations,
}
impl Task {
    /// Read projection omits native payloads, credentials, command lines and download locations.
    pub fn summary(&self) -> Result<TaskSummary, Error> {
        use rss_mdm_agent_wire::runtime::TaskPlatform as P;
        use rss_mdm_apple_mdm::native::request::Request as A;
        use rss_mdm_windows_mdm::native::Execution as W;
        let (platform, kind, name, objects) = match self {
            Self::Windows {
                request: W::SyncMl { request },
            } => (
                P::Windows,
                TaskKind::SyncMl,
                "SyncML".into(),
                request
                    .objects()
                    .map_err(|_| Error::Malformed)?
                    .into_iter()
                    .map(|o| o.key().to_owned())
                    .collect(),
            ),
            Self::Windows {
                request: W::Msi { job },
            } => (
                P::Windows,
                TaskKind::Msi,
                "MSI".into(),
                vec![job.product.clone()],
            ),
            Self::Macos { request } => match request {
                A::Command { command } => (
                    P::Macos,
                    TaskKind::Command,
                    command.request_type.clone(),
                    vec![],
                ),
                A::InstallProfile { profile } => (
                    P::Macos,
                    TaskKind::InstallProfile,
                    "InstallProfile".into(),
                    vec![profile.identifier.clone()],
                ),
                A::RemoveProfile { identifier, .. } => (
                    P::Macos,
                    TaskKind::RemoveProfile,
                    "RemoveProfile".into(),
                    vec![identifier.clone()],
                ),
                A::Declarations { declarations, .. } => (
                    P::Macos,
                    TaskKind::Declarations,
                    "DeclarativeManagement".into(),
                    declarations.iter().map(|d| d.identifier.clone()).collect(),
                ),
            },
        };
        Ok(TaskSummary {
            platform,
            kind,
            name,
            objects,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum DispatchFailure {
    Macos {
        reason: String,
    },
    Windows {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        phase: Option<AttemptPhase>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<rss_mdm_windows_mdm::native::Context>,
    },
}
