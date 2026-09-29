//! V4 channel enrollment contracts. Device identity is derived from transport proof.
use crate::{Capability, Secret, TaskArchitecture, TaskPlatform, WireError, strict_uuid};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Local OS evidence relative to the Agent's authenticated organization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MdmEnrollmentState {
    /// Positive evidence that no MDM enrollment exists.
    Unenrolled,
    /// Enrollment is owned by this organization.
    ThisOrganization,
    /// Enrollment is owned by another organization.
    OtherOrganization,
    /// The OS state could not be determined.
    Unknown,
}
impl MdmEnrollmentState {
    /// Closed inventory dictionary value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unenrolled => "unenrolled",
            Self::ThisOrganization => "this_organization",
            Self::OtherOrganization => "other_organization",
            Self::Unknown => "unknown",
        }
    }
}
/// Unattended registration submitted on the native MDM TLS listener.
/// The operation is a public coordinate, never a bearer credential or device identity claim.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedRegistrationRequest {
    /// Exact protocol major.
    #[serde(deserialize_with = "crate::tasks::version")]
    pub wire_version: u8,
    /// Stable Agent-selected retry identity.
    #[serde(with = "strict_uuid")]
    pub operation_id: Uuid,
    /// Native installation operation that authorized this one registration.
    #[serde(with = "strict_uuid")]
    pub installation_operation: Uuid,
    /// Agent-generated long-term credential; never embedded in the installer.
    pub credential: Secret,
    /// Supported ordered capability profile.
    #[serde(deserialize_with = "capabilities")]
    pub capabilities: Vec<Capability>,
    /// Locally verified operating system.
    pub platform: TaskPlatform,
    /// Locally verified processor architecture.
    pub architecture: TaskArchitecture,
}
impl ManagedRegistrationRequest {
    /// Validate producer-created values as well as strict decoded values.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.wire_version != crate::WIRE_VERSION
            || self.operation_id.is_nil()
            || self.installation_operation.is_nil()
            || !crate::supported_capabilities(&self.capabilities)
        {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}

fn capabilities<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Capability>, D::Error> {
    let value = Vec::<Capability>::deserialize(d)?;
    if !crate::supported_capabilities(&value) {
        return Err(serde::de::Error::custom(WireError::InvalidValue));
    }
    Ok(value)
}

/// Platform-owned enrollment entry; opening it never proves enrollment completed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentEntry {
    /// Open Windows' standard device-enrollment UI for this HTTPS discovery authority.
    Windows {
        /// Organization's discovery server.
        server: String,
    },
    /// Open the organization's HTTPS profile enrollment page; user/system approval remains required.
    Macos {
        /// Organization's managed enrollment entry.
        url: String,
    },
}
impl EnrollmentEntry {
    /// Require the platform's standard HTTPS entry and exclude embedded credentials.
    pub fn validate(&self, platform: TaskPlatform) -> Result<(), WireError> {
        let value = match (self, platform) {
            (Self::Windows { server }, TaskPlatform::Windows) => server,
            (Self::Macos { url }, TaskPlatform::Macos) => url,
            _ => return Err(WireError::InvalidValue),
        };
        let url = url::Url::parse(value).map_err(|_| WireError::InvalidValue)?;
        if value.len() > 2048
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || value.chars().any(char::is_control)
        {
            return Err(WireError::InvalidValue);
        }
        if matches!(self, Self::Windows { .. }) && (url.path() != "/" || url.query().is_some()) {
            return Err(WireError::InvalidValue);
        }
        Ok(())
    }
}
/// Signed request to open a standard MDM enrollment entry with normal OS approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentTaskSpec {
    /// Exact wire major.
    pub wire_version: u8,
    /// Enrolled tenant.
    #[serde(with = "strict_uuid")]
    pub tenant_id: Uuid,
    /// Independent source Agent device.
    pub device_id: String,
    /// Actual local operating system.
    pub platform: TaskPlatform,
    /// Actual local processor architecture.
    pub architecture: TaskArchitecture,
    /// Current Agent registration.
    #[serde(with = "strict_uuid")]
    pub registration_id: Uuid,
    /// Current Agent generation.
    pub generation: u64,
    /// Durable action run.
    #[serde(with = "strict_uuid")]
    pub task_id: Uuid,
    /// Exact delivery attempt.
    #[serde(with = "strict_uuid")]
    pub attempt_id: Uuid,
    /// Offer or explicit start permission.
    pub permit: crate::TaskPermit,
    /// Expiry of this signed permission.
    pub expires_at: i64,
    /// Target organization, fixed by server configuration and Policy publication.
    #[serde(with = "strict_uuid")]
    pub organization: Uuid,
    /// Standard platform enrollment entry, never an executable or installation script.
    pub entry: EnrollmentEntry,
}
impl EnrollmentTaskSpec {
    /// Canonical signature domain, bound to every identity and enrollment input.
    pub fn signing_bytes(&self, key_id: &str) -> Result<Vec<u8>, WireError> {
        self.entry.validate(self.platform)?;
        if self.wire_version != crate::WIRE_VERSION
            || self.tenant_id.is_nil()
            || self.organization != self.tenant_id
            || self.registration_id.is_nil()
            || self.task_id.is_nil()
            || self.attempt_id.is_nil()
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.expires_at <= 0
            || self.device_id.is_empty()
            || self.device_id.len() > 256
            || self.device_id.chars().any(char::is_control)
            || key_id.is_empty()
            || key_id.len() > 128
            || key_id.chars().any(char::is_control)
        {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = b"rss-mdm-agent-mdm-enrollment-v4-ed25519\0".to_vec();
        bytes.extend(serde_json::to_vec(&(key_id, self)).map_err(|_| WireError::InvalidValue)?);
        Ok(bytes)
    }
}
/// Outcome of asking the OS to open its enrollment UI; never a claim of active MDM authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentEntryOutcome {
    /// Entry opened; enrollment still awaits independent observation and MDM registration.
    Opened,
    /// The OS requires a logged-in user or explicit approval.
    UserRequired,
    /// Another MDM owns enrollment.
    ThirdPartyConflict,
    /// The local platform does not support this entry.
    Unsupported,
    /// Opening failed.
    Failed,
    /// Result is uncertain; reconcile local state before attempting again.
    Unknown,
}
