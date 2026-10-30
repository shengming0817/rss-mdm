//! MDM-owned subscriptions and event fanout; RSS owns execution and recovery.
//! ref: svix server/svix-server/src/core/message_app.rs@5e53ee906261197cf48c06a40ec2fcca1d40c420
#![forbid(unsafe_code)]
pub mod directory;
pub mod events;
pub mod fanout;
pub mod management;
pub mod materials;
pub mod model;
pub mod network;
mod presentation;
pub mod storage;
pub mod worker;
pub use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
pub use rss_transactional_messaging_webhook as transport;
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
pub const PAGE: i64 = 32;
pub const MAX_SUBSCRIPTIONS: i64 = 1000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("webhook identity rejected")]
    Unauthorized,
    #[error("webhook rollback unconfirmed")]
    RollbackFailed,
    #[error("webhook deadline elapsed")]
    Deadline,
    #[error("webhook audit failure: {0:?}")]
    Audit(rss_mdm_audit_integration::ErrorClass),
    #[error("invalid webhook input")]
    Invalid,
    #[error("webhook not found")]
    NotFound,
    #[error("webhook revision or operation conflict")]
    Conflict,
    #[error("webhook authority denied")]
    Denied,
    #[error("webhook storage unavailable")]
    Storage,
    #[error("webhook transaction outcome unknown")]
    CommitUnknown,
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}
impl From<PgError> for Error {
    fn from(_: PgError) -> Self {
        Self::Storage
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Invalid
    }
}
impl From<Error> for PgError {
    fn from(error: Error) -> Self {
        use rss_transactional_messaging::error::MessagingErrorKind;
        let kind = match error {
            Error::Conflict => MessagingErrorKind::Conflict,
            Error::Storage
            | Error::CommitUnknown
            | Error::RollbackFailed
            | Error::Deadline
            | Error::Audit(_) => MessagingErrorKind::Transient,
            _ => MessagingErrorKind::Permanent,
        };
        PgError::Operation {
            kind,
            source: rss_redact::RedactedSource::new(error),
        }
    }
}

pub const ACCESS_CONTRACT: &str = include_str!("../schema/access-contract.json");

impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(error: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        rss_mdm_authorization_service::Error::from(error).into()
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as E;
        match error {
            E::Malformed => Self::Invalid,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Denied,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Deadline => Self::Deadline,
            E::Audit(error) => Self::Audit(error.class()),
            E::Corrupt | E::Storage | E::Configuration => Self::Storage,
        }
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(error: rss_mdm_audit_integration::Error) -> Self {
        Self::Audit(error.class())
    }
}
impl From<&rss_mdm_audit_integration::Error> for Error {
    fn from(error: &rss_mdm_audit_integration::Error) -> Self {
        Self::Audit(error.class())
    }
}
