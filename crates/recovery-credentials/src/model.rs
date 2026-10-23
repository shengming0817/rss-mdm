use rss_mdm_authorization_service::Permission;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Closed errors never contain platform responses, key files or supplied material.
#[derive(Clone, Debug, thiserror::Error, Serialize)]
pub enum Error {
    #[error("invalid recovery credential input")]
    Malformed,
    #[error("recovery credential configuration invalid")]
    Configuration,
    #[error("authentication required")]
    Unauthorized,
    #[error("recovery credential access denied")]
    Forbidden,
    #[error("recovery credential not found")]
    NotFound,
    #[error("recovery credential version conflicts")]
    Conflict,
    #[error("recovery credential integrity failure")]
    Integrity,
    #[error("recovery credential dependency unavailable")]
    Storage,
    #[error("recovery credential audit failed")]
    Audit,
    #[error("recovery credential commit unknown")]
    CommitUnknown,
    #[error("recovery credential rollback unconfirmed")]
    RollbackFailed,
    #[error("recovery credential operation unsupported")]
    Unsupported,
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(value: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as E;
        match value {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::NotFound => Self::NotFound,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            _ => Self::Storage,
        }
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(_: rss_mdm_audit_integration::Error) -> Self {
        Self::Audit
    }
}
impl From<rss_audit_postgres::Error> for Error {
    fn from(_: rss_audit_postgres::Error) -> Self {
        Self::Audit
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(value: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as E;
        match value {
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            _ => Self::Storage,
        }
    }
}

/// Stable platform coordinates. Display names and drive letters are not identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Subject {
    /// RSS offline additional-factor recovery, never the Windows account password.
    RssLogin {
        binding: Uuid,
        binding_generation: i64,
        sid: String,
    },
    Bitlocker {
        volume: String,
        protector: Uuid,
    },
    LocalAdministrator {
        sid: String,
    },
    /// Apple native PRK commands address the startup volume, not a caller-selected disk.
    Filevault,
    RecoveryLock,
    LockPin {
        operation: Uuid,
    },
}
impl Subject {
    pub fn validate(&self) -> Result<(), Error> {
        let bounded = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        let valid = match self {
            Self::Bitlocker { volume, protector } => bounded(volume) && !protector.is_nil(),
            Self::RssLogin {
                binding,
                binding_generation,
                sid,
            } => {
                !binding.is_nil()
                    && *binding_generation > 0
                    && rss_mdm_agent_wire::runtime::AccessAccount::Windows { sid: sid.clone() }
                        .validate()
                        .is_ok()
            }
            Self::Filevault => true,
            Self::LocalAdministrator { sid } => {
                sid.starts_with("S-1-5-")
                    && bounded(sid)
                    && sid
                        .split('-')
                        .skip(1)
                        .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            }
            Self::LockPin { operation } => !operation.is_nil(),
            Self::RecoveryLock => true,
        };
        if valid { Ok(()) } else { Err(Error::Malformed) }
    }
    pub fn permission(&self) -> Permission {
        match self {
            Self::RssLogin { .. } | Self::LocalAdministrator { .. } => Permission::AccountWrite,
            Self::LockPin { .. } => Permission::DeviceControl,
            _ => Permission::SecurityOperate,
        }
    }
    pub(crate) fn validate_secret(&self, value: &[u8]) -> Result<(), Error> {
        let valid = match self {
            Self::RssLogin { .. } => {
                use base64::Engine;
                std::str::from_utf8(value).is_ok_and(|s| {
                    s.len() == 43
                        && base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(s)
                            .is_ok_and(|bytes| {
                                bytes.len() == 32
                                    && base64::engine::general_purpose::URL_SAFE_NO_PAD
                                        .encode(bytes)
                                        == s
                            })
                })
            }
            Self::LockPin { .. } => value.len() == 6 && value.iter().all(u8::is_ascii_digit),
            Self::Bitlocker { .. } => std::str::from_utf8(value).is_ok_and(|s| {
                let groups: Vec<_> = s.split('-').collect();
                groups.len() == 8
                    && groups.iter().all(|g| {
                        g.len() == 6
                            && g.bytes().all(|b| b.is_ascii_digit())
                            && g.parse::<u32>().is_ok_and(|n| n < 720896 && n % 11 == 0)
                    })
            }),
            _ => {
                !value.is_empty()
                    && value.len() <= 4096
                    && std::str::from_utf8(value).is_ok_and(|s| !s.contains('\0'))
            }
        };
        if valid { Ok(()) } else { Err(Error::Malformed) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub device: String,
    pub registration: Uuid,
    pub generation: i64,
    pub subject: Subject,
}
impl Binding {
    pub fn validate(&self) -> Result<(), Error> {
        if self.device.is_empty()
            || self.device.len() > 256
            || self.registration.is_nil()
            || self.generation < 1
        {
            return Err(Error::Malformed);
        }
        self.subject.validate()
    }
}

/// Evidence of validity is independent of whether bytes are safely escrowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validity {
    Unverified,
    Verified,
    Unknown,
    Superseded,
    Revoked,
}
impl Validity {
    pub fn readable(self) -> bool {
        matches!(self, Self::Unverified | Self::Verified | Self::Unknown)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Material {
    pub id: Uuid,
    pub binding: Binding,
    pub version: i64,
    pub current: bool,
    pub validity: Validity,
    pub escrowed: bool,
    pub operation: Uuid,
    pub created_at: i64,
    pub invalidated_at: Option<i64>,
}
/// Only the explicit secret response serializes plaintext. Debug is always redacted.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Disclosure {
    pub material: Material,
    pub secret: Zeroizing<String>,
}
impl std::fmt::Debug for Disclosure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Disclosure([REDACTED])")
    }
}

/// Identity of one immutable material version, used as authenticated encryption context.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Coordinates {
    pub tenant: Uuid,
    pub material: Uuid,
    pub binding: Binding,
    pub version: i64,
}
impl Coordinates {
    pub fn validate(&self) -> Result<(), Error> {
        if self.tenant.is_nil() || self.material.is_nil() || self.version < 1 {
            return Err(Error::Malformed);
        }
        self.binding.validate()
    }
}
