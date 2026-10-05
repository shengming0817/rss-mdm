//! Current locally reported execution context, distinct from capabilities and scope.
use crate::runtime::{TaskPlatform, WireError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Complete current native execution environment reported by this registration.
pub struct SoftwareExecutionContext {
    /// Strictly increasing local context generation; retries retain the same value.
    #[schemars(extend("minimum" = 1, "maximum" = 9223372036854775807u64))]
    pub revision: u64,
    /// Current native Windows sideload policy.
    pub msix_sideload: bool,
    /// Current native API support for explicitly approved unsigned packages.
    pub msix_unsigned: bool,
    /// Complete numeric OS version, not an inferred product/platform string.
    #[schemars(extend("not" = serde_json::json!({"const": ([0u16; 4])})))]
    pub os_version: [u16; 4],
    /// Whether the native system broker is available in this Agent installation.
    pub system_broker: bool,
    /// Whether a helper is bound to this exact live interactive session.
    pub user_helper: bool,
    /// Exact live interactive session, when one exists.
    #[serde(deserialize_with = "super::required_option")]
    #[schemars(
        required,
        schema_with = "crate::self_service::nullable_schema::<SoftwareInteractiveUser>"
    )]
    pub interactive_user: Option<SoftwareInteractiveUser>,
    /// Source-scoped read credential references actually available locally.
    #[schemars(extend("maxItems" = 16, "uniqueItems" = true))]
    pub source_credentials: Vec<SoftwareReadCredential>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// One concrete live OS session.
pub struct SoftwareInteractiveUser {
    /// Windows SID or macOS numeric UID.
    #[schemars(length(min = 1, max = 184), regex(pattern = "^[^\\x00-\\x1f\\x7f]+$"))]
    pub identity: String,
    /// Changes on logoff/login; identical account names cannot reuse a previous session.
    #[serde(with = "crate::runtime::strict_uuid")]
    #[schemars(schema_with = "crate::runtime::uuid_schema")]
    pub session_id: Uuid,
    /// Privilege needed by the exact native profile, not a generic authorization grant.
    pub administrator: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Availability of a particular source read credential in the local Agent.
pub struct SoftwareReadCredential {
    /// Exact source identity in the consuming tenant.
    #[schemars(length(min = 1, max = 128), regex(pattern = "^[^\\x00-\\x1f\\x7f]+$"))]
    pub source: String,
    /// Host-provisioned opaque credential reference; never token bytes or a URL.
    #[schemars(length(min = 1, max = 128), regex(pattern = "^[^\\x00-\\x1f\\x7f]+$"))]
    pub reference: String,
}
impl SoftwareExecutionContext {
    /// Validate the exact OS identity rather than accepting account labels.
    pub fn validate_for(&self, platform: TaskPlatform) -> Result<(), WireError> {
        self.validate()?;
        if let Some(u) = &self.interactive_user {
            let valid = valid_os_identity(&u.identity, platform);
            if !valid {
                return Err(WireError::InvalidValue);
            }
        }
        if platform == TaskPlatform::Macos && (self.msix_sideload || self.msix_unsigned) {
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
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
        #[schemars(extend("minLength" = 1, "maxLength" = 184, "pattern" = "^[^\\x00-\\x1f\\x7f]+$"))]
        identity: String,
        /// Exact login generation.
        #[serde(with = "crate::runtime::strict_uuid")]
        #[schemars(schema_with = "crate::runtime::uuid_schema")]
        session_id: Uuid,
    },
}
impl SoftwareExecutionTarget {
    /// Validate the exact OS identity and login generation of a signed target.
    pub fn validate_for(&self, platform: TaskPlatform) -> Result<(), WireError> {
        match self {
            Self::Device => Ok(()),
            Self::User {
                identity,
                session_id,
            } if !session_id.is_nil()
                && identity.len() <= 184
                && valid_os_identity(identity, platform) =>
            {
                Ok(())
            }
            _ => Err(WireError::InvalidValue),
        }
    }
}
fn valid_os_identity(identity: &str, platform: TaskPlatform) -> bool {
    match platform {
        TaskPlatform::Windows => identity.strip_prefix("S-1-").is_some_and(|tail| {
            tail.split('-').count() >= 2
                && tail
                    .split('-')
                    .all(|n| !n.is_empty() && n.parse::<u32>().is_ok())
        }),
        TaskPlatform::Macos => {
            identity.parse::<u32>().is_ok() && identity.bytes().all(|b| b.is_ascii_digit())
        }
    }
}
