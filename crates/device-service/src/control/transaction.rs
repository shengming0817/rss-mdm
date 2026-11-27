//! Host transaction settlement for execution and action-plan requests.
use crate::control::{Error, Failure};
use rss_transactional_messaging_postgres::PgError;
#[derive(Debug, thiserror::Error)]
pub enum Fault {
    #[error(transparent)]
    Request(#[from] Error),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}
pub type Result<T> = std::result::Result<T, Fault>;
pub fn checked_input<T>(value: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    value.map_err(|_| Error::Malformed.into())
}
pub fn stored<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Unavailable(Failure::CommandStorage).into())
}
pub fn checked<T>(r: std::result::Result<T, impl std::fmt::Debug>) -> Result<T> {
    r.map_err(|_| Error::Conflict.into())
}
pub fn json(v: &impl serde::Serialize) -> Result<Value> {
    checked_input(serde_json::to_value(v))
}
use rss_mdm_audit_integration::command_transaction as shared;
pub use rss_mdm_audit_integration::command_transaction::deadline;
pub type Transaction = shared::Transaction<Fault>;

impl shared::CommandFault for Fault {
    type Error = Error;
    fn into_rejection(self) -> shared::Rejection<Error> {
        match self {
            Self::Request(error) => shared::Rejection::Request(error),
            Self::Storage(error) => shared::Rejection::Storage(error),
            Self::Sql(error) => shared::Rejection::Sql(error),
        }
    }
}
impl From<shared::Failure> for Error {
    fn from(error: shared::Failure) -> Self {
        match error {
            shared::Failure::Storage => Self::Unavailable(Failure::CommandStorage),
            shared::Failure::Invariant => Self::Unavailable(Failure::CommandInvariant),
            shared::Failure::Conflict => Self::Conflict,
            shared::Failure::CommitUnknown => Self::CommitUnknown,
            shared::Failure::RollbackFailed => Self::RollbackFailed,
        }
    }
}
impl From<crate::control::authorization::error::AuthorizationError> for Fault {
    fn from(error: crate::control::authorization::error::AuthorizationError) -> Self {
        Error::from(error).into()
    }
}

impl From<rss_mdm_audit_integration::Error> for Fault {
    fn from(error: rss_mdm_audit_integration::Error) -> Self {
        Self::Request(error.into())
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Fault {
    fn from(error: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self::Request(rss_mdm_audit_integration::Error::Fact(error).into())
    }
}

use sha2::{Digest, Sha256};
pub fn fingerprint(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    Ok(Sha256::digest(checked_input(serde_json::to_vec(value))?).to_vec())
}

use serde_json::Value;
impl From<crate::control::device::DeviceError> for Fault {
    fn from(error: crate::control::device::DeviceError) -> Self {
        Error::from(error).into()
    }
}

impl From<rss_mdm_policy::Error> for Error {
    fn from(value: rss_mdm_policy::Error) -> Self {
        match value {
            rss_mdm_policy::Error::Malformed => Self::Malformed,
            rss_mdm_policy::Error::Conflict => Self::Conflict,
            rss_mdm_policy::Error::NotFound => Self::NotFound,
        }
    }
}
impl From<rss_mdm_policy::Error> for Fault {
    fn from(value: rss_mdm_policy::Error) -> Self {
        Self::Request(value.into())
    }
}

impl From<rss_mdm_authorization_service::Error> for Fault {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        Self::Request(error.into())
    }
}

impl From<rss_mdm_registration_service::Error> for Fault {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self::from(Error::from(e))
    }
}

impl From<rss_mdm_inventory_service::Error> for Fault {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        Self::from(Error::from(e))
    }
}

impl From<rss_mdm_inventory_service::transaction::Fault> for Fault {
    fn from(e: rss_mdm_inventory_service::transaction::Fault) -> Self {
        use rss_mdm_inventory_service::transaction::Fault as I;
        match e {
            I::Request(e) => Self::Request(e.into()),
            I::Storage(e) => Self::Storage(e),
            I::Sql(e) => Self::Sql(e),
        }
    }
}

impl From<rss_mdm_task_state::Error> for Fault {
    fn from(error: rss_mdm_task_state::Error) -> Self {
        Self::Request(error.into())
    }
}

impl From<rss_mdm_registration_service::command_authority::CommandAuthorityError> for Fault {
    fn from(e: rss_mdm_registration_service::command_authority::CommandAuthorityError) -> Self {
        use rss_mdm_registration_service::command_authority::CommandAuthorityError as E;
        match e {
            E::Storage(e) => Self::Storage(e),
            E::Sql(e) => Self::Sql(e),
            E::Registration(e) => Error::from(e).into(),
            E::Conflict => Error::Conflict.into(),
        }
    }
}
