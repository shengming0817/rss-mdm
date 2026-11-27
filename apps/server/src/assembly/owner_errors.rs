//! Closed business-owner errors at the application boundary.
use super::query_snapshot::sql;
use rss_mdm_management_http::{Error, Failure};

pub(super) fn software(e: rss_mdm_software_service::deployment::Error) -> crate::Error {
    use rss_mdm_software_service::deployment::Error as E;
    match e {
        E::CommitUnknown => crate::Error::CommitUnknown,
        E::RollbackFailed => crate::Error::RollbackFailed,
        E::Malformed => crate::Error::Malformed,
        E::Unauthorized => crate::Error::Unauthorized,
        E::Forbidden => crate::Error::Forbidden,
        E::Conflict => crate::Error::Conflict,
        E::NotFound => crate::Error::NotFound,
        _ => crate::Error::Unavailable(crate::Failure::CommandStorage),
    }
}
pub(super) fn installation(e: rss_mdm_registration_service::installation::Error) -> crate::Error {
    use rss_mdm_registration_service::installation::Error as E;
    match e {
        E::CommitUnknown => crate::Error::CommitUnknown,
        E::RollbackFailed => crate::Error::RollbackFailed,
        E::Malformed => crate::Error::Malformed,
        E::Unauthorized => crate::Error::Unauthorized,
        E::Forbidden => crate::Error::Forbidden,
        E::Conflict => crate::Error::Conflict,
        E::NotFound => crate::Error::NotFound,
        _ => crate::Error::Unavailable(crate::Failure::CommandStorage),
    }
}
pub(super) fn enrollment(
    e: rss_mdm_registration_service::enrollment::tasks::Error,
) -> crate::Error {
    use rss_mdm_registration_service::enrollment::tasks::Error as E;
    match e {
        E::CommitUnknown => crate::Error::CommitUnknown,
        E::RollbackFailed => crate::Error::RollbackFailed,
        E::Malformed => crate::Error::Malformed,
        E::Unauthorized => crate::Error::Unauthorized,
        E::Forbidden => crate::Error::Forbidden,
        E::Conflict => crate::Error::Conflict,
        E::NotFound => crate::Error::NotFound,
        _ => crate::Error::Unavailable(crate::Failure::CommandStorage),
    }
}

pub(super) fn software_http(
    e: rss_mdm_software_service::deployment::Error,
) -> rss_mdm_management_http::Error {
    rss_mdm_software_service::deployment::queries::QueryError::from(e).into()
}
pub(super) fn enrollment_http(
    e: rss_mdm_registration_service::enrollment::tasks::Error,
) -> rss_mdm_management_http::Error {
    use rss_mdm_management_http::{Error as H, Failure};
    use rss_mdm_registration_service::enrollment::tasks::Error as E;
    match e {
        E::CommitUnknown => H::CommitUnknown,
        E::RollbackFailed => H::RollbackFailed,
        E::Malformed => H::Malformed,
        E::Unauthorized => H::Unauthorized,
        E::Forbidden => H::Forbidden,
        E::Conflict => H::Conflict,
        E::NotFound => H::NotFound,
        _ => H::Unavailable(Failure::CommandStorage),
    }
}
pub(super) fn installation_http(
    e: rss_mdm_registration_service::installation::Error,
) -> rss_mdm_management_http::Error {
    use rss_mdm_management_http::{Error as H, Failure};
    use rss_mdm_registration_service::installation::Error as E;
    match e {
        E::CommitUnknown => H::CommitUnknown,
        E::RollbackFailed => H::RollbackFailed,
        E::Malformed => H::Malformed,
        E::Unauthorized => H::Unauthorized,
        E::Forbidden => H::Forbidden,
        E::Conflict => H::Conflict,
        E::NotFound => H::NotFound,
        E::Unsupported => H::Unsupported,
        E::ReadConflict => H::QueryReadConflict,
        E::CursorInvalidated => H::QueryCursorInvalidated,
        _ => H::Unavailable(Failure::CommandStorage),
    }
}

pub(super) fn access(
    e: rss_mdm_device_access_postgres::device_access::execution::Error,
) -> crate::Error {
    use rss_mdm_device_access_postgres::device_access::execution::Error as E;
    match e {
        E::CommitUnknown => crate::Error::CommitUnknown,
        E::RollbackFailed => crate::Error::RollbackFailed,
        E::Malformed => crate::Error::Malformed,
        E::Unauthorized => crate::Error::Unauthorized,
        E::Forbidden => crate::Error::Forbidden,
        E::Conflict => crate::Error::Conflict,
        E::NotFound => crate::Error::NotFound,
        _ => crate::Error::Unavailable(crate::Failure::CommandStorage),
    }
}

pub(super) fn credential(e: rss_mdm_recovery_credentials::tasks::Error) -> crate::Error {
    use rss_mdm_recovery_credentials::tasks::Error as E;
    match e {
        E::CommitUnknown => crate::Error::CommitUnknown,
        E::RollbackFailed => crate::Error::RollbackFailed,
        E::Malformed => crate::Error::Malformed,
        E::Unauthorized => crate::Error::Unauthorized,
        E::Forbidden => crate::Error::Forbidden,
        E::Conflict => crate::Error::Conflict,
        E::NotFound => crate::Error::NotFound,
        _ => crate::Error::Unavailable(crate::Failure::CommandStorage),
    }
}

pub(super) fn credential_native(e: rss_mdm_recovery_credentials::native::Error) -> crate::Error {
    use rss_mdm_recovery_credentials::native::Error as E;
    match e {
        E::CommitUnknown => crate::Error::CommitUnknown,
        E::RollbackFailed => crate::Error::RollbackFailed,
        E::Malformed => crate::Error::Malformed,
        E::Unauthorized => crate::Error::Unauthorized,
        E::Forbidden => crate::Error::Forbidden,
        E::Conflict => crate::Error::Conflict,
        E::NotFound => crate::Error::NotFound,
        _ => crate::Error::Unavailable(crate::Failure::CommandStorage),
    }
}

pub(super) fn script(error: rss_mdm_script_service::Error) -> Error {
    use rss_mdm_script_service::Error as S;
    match error {
        S::Unsupported => Error::Unsupported,
        S::Malformed => Error::Malformed,
        S::Conflict => Error::Conflict,
        S::Forbidden => Error::Forbidden,
        S::Unauthorized => Error::Unauthorized,
        S::NotFound => Error::NotFound,
        S::CommitUnknown => Error::CommitUnknown,
        S::RollbackFailed => Error::RollbackFailed,
        S::Inventory(e) => e.into(),
        S::Content(e) => e.into(),
        S::Invariant => Error::Unavailable(Failure::CommandInvariant),
        S::Unavailable => Error::Unavailable(Failure::CommandStorage),
        S::Audit(_) => Error::Unavailable(Failure::Audit),
    }
}

pub(super) fn script_fault(error: rss_mdm_script_service::transaction::Fault) -> Error {
    use rss_mdm_script_service::transaction::Fault as F;
    match error {
        F::Request(e) => script(e),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}

pub(super) fn software_fault(
    error: rss_mdm_software_service::deployment::transaction::Fault,
) -> Error {
    use rss_mdm_software_service::deployment::transaction::Fault as F;
    match error {
        F::Request(e) => software_http(e),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}

pub(super) fn enrollment_fault(
    error: rss_mdm_registration_service::enrollment::tasks::transaction::Fault,
) -> Error {
    use rss_mdm_registration_service::enrollment::tasks::transaction::Fault as F;
    match error {
        F::Request(e) => enrollment_http(e),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}

pub(super) fn access_fault(
    e: rss_mdm_device_access_postgres::device_access::execution::transaction::Fault,
) -> Error {
    use rss_mdm_device_access_postgres::device_access::execution::{
        Error as E, transaction::Fault as F,
    };
    match e {
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
        F::Request(e) => match e {
            E::Malformed => Error::Malformed,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::NotFound => Error::NotFound,
            E::Conflict => Error::Conflict,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Unsupported => Error::Unsupported,
            E::Audit(_) => Error::Unavailable(Failure::Audit),
            _ => Error::Unavailable(Failure::CommandInvariant),
        },
    }
}

pub(super) fn credential_fault(
    e: rss_mdm_recovery_credentials::tasks::transaction::Fault,
) -> Error {
    use rss_mdm_recovery_credentials::tasks::{Error as E, transaction::Fault as F};
    match e {
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
        F::Request(e) => match e {
            E::Malformed => Error::Malformed,
            E::Forbidden => Error::Forbidden,
            E::Unauthorized => Error::Unauthorized,
            E::NotFound => Error::NotFound,
            E::Conflict => Error::Conflict,
            E::CommitUnknown => Error::CommitUnknown,
            E::RollbackFailed => Error::RollbackFailed,
            E::Unsupported => Error::Unsupported,
            E::Audit(_) => Error::Unavailable(Failure::Audit),
            _ => Error::Unavailable(Failure::CommandInvariant),
        },
    }
}

pub(super) fn configuration_fault(e: rss_mdm_policy_service::transaction::Fault) -> Error {
    match e {
        rss_mdm_policy_service::transaction::Fault::Request(e) => e.into(),
        rss_mdm_policy_service::transaction::Fault::Sql(e) => sql(e),
        rss_mdm_policy_service::transaction::Fault::Storage(_) => {
            Error::Unavailable(Failure::Database)
        }
    }
}

pub(super) fn device_control_fault(
    error: rss_mdm_device_service::control::transaction::Fault,
) -> Error {
    use rss_mdm_device_service::control::transaction::Fault as F;
    match error {
        F::Request(e) => e.into(),
        F::Sql(e) => sql(e),
        F::Storage(_) => Error::Unavailable(Failure::Database),
    }
}
