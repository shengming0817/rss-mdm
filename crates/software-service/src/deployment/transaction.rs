//! Host transaction settlement for execution and action-plan requests.
use crate::deployment::{Error, Failure};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
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
pub use rss_mdm_audit_integration::command_transaction::{TRANSACTION_BUDGET, deadline};
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
impl From<crate::deployment::authorization::error::AuthorizationError> for Fault {
    fn from(error: crate::deployment::authorization::error::AuthorizationError) -> Self {
        Error::from(error).into()
    }
}

use rss_mdm_audit_integration::RequestAudit;

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
impl From<crate::deployment::device::DeviceError> for Fault {
    fn from(error: crate::deployment::device::DeviceError) -> Self {
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

use crate::catalog;
impl From<catalog::Error> for Fault {
    fn from(e: catalog::Error) -> Self {
        match e {
            catalog::Error::Storage(e) => Self::Storage(e),
            catalog::Error::Sql(e) => Self::Sql(e),
            catalog::Error::Audit(e) => Self::from(e),
            catalog::Error::Fact(e) => Self::from(e),
            catalog::Error::Input => Error::Malformed.into(),
            catalog::Error::Capacity => Error::Unavailable(Failure::Capacity).into(),
            catalog::Error::Unsupported => Error::Unsupported.into(),
            catalog::Error::Dependency => Error::Forbidden.into(),
            catalog::Error::Conflict => Error::Conflict.into(),
            catalog::Error::NotAdmitted => Error::Forbidden.into(),
            catalog::Error::Missing => {
                Error::Resource(crate::deployment::error::ResourceError::Missing).into()
            }
            catalog::Error::Integrity => {
                Error::Unavailable(crate::deployment::Failure::SoftwareCatalogInvariant).into()
            }
            catalog::Error::Content => {
                Error::Unavailable(crate::deployment::Failure::ContentInvariant).into()
            }
        }
    }
}

impl From<crate::deployment::scope::SourceError> for Fault {
    fn from(e: crate::deployment::scope::SourceError) -> Self {
        use crate::deployment::scope::SourceError as S;
        match e {
            S::Unsupported => Error::Unsupported.into(),
            S::Missing => Error::NotFound.into(),
            S::Capacity => Error::Unavailable(Failure::Capacity).into(),
            S::Conflict => Error::Conflict.into(),
            S::Invariant => Error::Unavailable(Failure::PlanningStorage).into(),
            S::Storage(e) => Self::Sql(e),
        }
    }
}
impl From<crate::deployment::scope::SourceError> for Error {
    fn from(e: crate::deployment::scope::SourceError) -> Self {
        match Fault::from(e) {
            Fault::Request(e) => e,
            Fault::Sql(_) | Fault::Storage(_) => Self::Unavailable(Failure::PlanningStorage),
        }
    }
}

pub(crate) async fn prepare_audit_in(
    store: &rss_mdm_audit_integration::AuditStore,
    tx: &mut PgTransaction<'_>,
    audit: &RequestAudit,
    business: &[rss_transactional_messaging::message::PartitionIdentity],
) -> std::result::Result<(), rss_mdm_audit_integration::Error> {
    store.prepare_in(tx, audit, business).await
}

/// One protected/source input batch, independent of the size of the filtered directory.
pub(crate) fn input_prefix(
    sizes: impl IntoIterator<Item = i64>,
) -> std::result::Result<usize, Error> {
    let mut bytes = 0i64;
    let mut count = 0;
    for size in sizes.into_iter().take(1000) {
        if !(0..=16 * 1024 * 1024).contains(&size) {
            return Err(Error::Unavailable(Failure::Capacity));
        }
        if bytes + size > 16 * 1024 * 1024 {
            break;
        }
        bytes += size;
        count += 1;
    }
    Ok(count)
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

impl From<rss_mdm_registration_service::installation::transaction::Fault> for Fault {
    fn from(value: rss_mdm_registration_service::installation::transaction::Fault) -> Self {
        use rss_mdm_registration_service::installation::{Error as E, transaction::Fault as F};
        match value {
            F::Storage(e) => Self::Storage(e),
            F::Sql(e) => Self::Sql(e),
            F::Request(e) => Self::Request(match e {
                E::CommitUnknown => Error::CommitUnknown,
                E::RollbackFailed => Error::RollbackFailed,
                E::Forbidden => Error::Forbidden,
                E::Unauthorized => Error::Unauthorized,
                E::Malformed => Error::Malformed,
                E::Conflict => Error::Conflict,
                _ => Error::Unavailable(Failure::CommandStorage),
            }),
        }
    }
}
