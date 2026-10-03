use crate::Error;
use rss_device_command::StateDigest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Common execution envelope carries target identity, never client-asserted OS or authorization facts.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeTarget {
    Device,
    User { user_id: String },
}
impl NativeTarget {
    pub(crate) fn matches_windows_context(&self, context: Option<Uuid>) -> bool {
        match self {
            Self::Device => true,
            Self::User { user_id } => context.is_some_and(|id| user_id == &id.to_string()),
        }
    }
    pub fn user_key(&self) -> &str {
        match self {
            Self::Device => "",
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
    pub fn source(&self) -> rss_mdm_inventory::ReportSource {
        match self {
            Self::Windows { .. } => rss_mdm_inventory::ReportSource::MdmWindows,
            Self::Macos { .. } => rss_mdm_inventory::ReportSource::MdmApple,
        }
    }
    pub fn permissions(&self) -> Result<Vec<crate::authorization::Permission>, Error> {
        super::permissions::required(self)
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
        device: &str,
    ) -> Result<StateDigest, Error> {
        let digest = crate::protection::fingerprint(
            protector,
            tenant,
            device,
            "native-input/v3",
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
                if (object.scope == rss_mdm_windows_mdm::native::Scope::User)
                    != matches!(self.target, NativeTarget::User { .. })
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
pub struct DispatchV3 {
    pub device: String,
    pub operation_id: Uuid,
    pub generation: i64,
    pub epoch: i64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub request_id: Uuid,
    pub expected_revision: i64,
}
#[cfg(test)]
#[path = "../tests/model_unit.rs"]
mod tests;

/// Native exchange phases; database values are decoded fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            _ => Err(Error::Unavailable(crate::Failure::CommandInvariant)),
        }
    }
}
#[cfg(test)]
#[path = "../tests/model_phase_unit.rs"]
mod phase_tests;

impl Task {
    /// Read projection omits native payloads, credentials, command lines and download locations.
    pub fn summary(&self) -> Result<serde_json::Value, Error> {
        use rss_mdm_apple_mdm::native::request::Request as A;
        use rss_mdm_windows_mdm::native::Execution as W;
        use serde_json::json;
        Ok(match self {
            Self::Windows {
                request: W::SyncMl { request },
            } => {
                json!({"platform":"windows","kind":"sync_ml","name":"SyncML","objects":request.objects().map_err(|_|Error::Malformed)?.into_iter().map(|o|o.uri).collect::<Vec<_>>()})
            }
            Self::Windows {
                request: W::Msi { job },
            } => json!({"platform":"windows","kind":"msi","name":"MSI","objects":[job.product]}),
            Self::Macos { request } => match request {
                A::Command { command } => {
                    json!({"platform":"macos","kind":"command","name":command.request_type,"objects":[]})
                }
                A::InstallProfile { profile } => {
                    json!({"platform":"macos","kind":"install_profile","name":"InstallProfile","objects":[profile.identifier]})
                }
                A::RemoveProfile { identifier, .. } => {
                    json!({"platform":"macos","kind":"remove_profile","name":"RemoveProfile","objects":[identifier]})
                }
                A::Declarations { declarations } => {
                    json!({"platform":"macos","kind":"declarations","name":"DeclarativeManagement","objects":declarations.iter().map(|d|&d.identifier).collect::<Vec<_>>()})
                }
            },
        })
    }
}
