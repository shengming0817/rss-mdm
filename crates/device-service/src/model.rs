use rss_mdm_registration_service::device::endpoints::PrimaryRegistration;
pub use rss_mdm_registration_service::device::endpoints::PrimaryRegistration as Member;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(schemars::JsonSchema, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Confirmed,
    NeedsVerification,
    Revoked,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Association {
    pub id: Uuid,
    pub version: i64,
    pub state: State,
    pub members: Vec<Member>,
    pub evidence: String,
    #[serde(skip_serializing, default)]
    pub hardware: std::collections::BTreeMap<String, crate::Hardware>,
    pub confirmed_by: String,
    pub confirmed_at: i64,
    pub revoked_by: Option<String>,
    pub revoked_at: Option<i64>,
    pub reason: Option<String>,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Confirm {
    pub operation_id: Uuid,
    /// None creates a relation with expectedVersion=0; Some re-verifies an existing one.
    pub association_id: Option<Uuid>,
    pub expected_version: i64,
    pub mdm: PrimaryRegistration,
    pub agent: PrimaryRegistration,
    /// Administrator's explicit verification record for an exceptional case.
    pub evidence: String,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revoke {
    pub operation_id: Uuid,
    pub expected_version: i64,
    pub reason: String,
}
#[derive(schemars::JsonSchema, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidatePage {
    pub items: Vec<Member>,
    /// Endpoint scan continuation, not an indication of any hidden candidate count.
    pub next_cursor: Option<String>,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("device query budget exceeded")]
    Capacity,
    #[error("invalid association request")]
    Malformed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("association not found")]
    NotFound,
    #[error("association version, membership or operation conflict")]
    Conflict,
    #[error("read authority changed during the request")]
    ReadConflict,
    #[error("fixed query result is no longer available")]
    ResultUnavailable,
    #[error("device view cursor invalidated")]
    CursorInvalidated,
    #[error("association storage unavailable")]
    Storage,
    #[error("association request deadline")]
    Deadline,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("rollback unconfirmed")]
    RollbackFailed,
    #[error(transparent)]
    Audit(#[from] rss_mdm_audit_integration::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        if e.as_database_error()
            .is_some_and(|e| e.is_unique_violation())
        {
            Self::Conflict
        } else {
            Self::Storage
        }
    }
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        use rss_mdm_authorization_service::error::AuthorizationError as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Corrupt => Self::Storage,
        }
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Deadline => Self::Deadline,
            _ => Self::Storage,
        }
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::Deadline => Self::Deadline,
            _ => Self::Storage,
        }
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self::Audit(e.into())
    }
}
pub(crate) fn transaction_error(e: rss_mdm_audit_integration::TransactionError<Error>) -> Error {
    match e {
        rss_mdm_audit_integration::TransactionError::Operation(e) => e,
        rss_mdm_audit_integration::TransactionError::Storage(e) => Error::Audit(e),
        rss_mdm_audit_integration::TransactionError::Rollback { .. } => Error::RollbackFailed,
    }
}
pub(crate) fn text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control)
}
