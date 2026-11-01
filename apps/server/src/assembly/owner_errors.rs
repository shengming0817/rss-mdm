//! Closed business-owner errors at the application boundary.
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
    e: rss_mdm_registration_service::device_access::execution::Error,
) -> crate::Error {
    use rss_mdm_registration_service::device_access::execution::Error as E;
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
