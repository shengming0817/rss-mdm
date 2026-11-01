#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("capability not enabled")]
    Unsupported,
    #[error("invalid script request")]
    Malformed,
    #[error("script execution conflict")]
    Conflict,
    #[error("permission denied")]
    Forbidden,
    #[error("identity rejected")]
    Unauthorized,
    #[error("script execution not found")]
    NotFound,
    #[error("script storage invariant violated")]
    Invariant,
    #[error("script dependency unavailable")]
    Unavailable,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("rollback not acknowledged; original attempt remains unresolved")]
    RollbackFailed,
    #[error(transparent)]
    Audit(#[from] std::sync::Arc<rss_mdm_audit_integration::Error>),
    #[error(transparent)]
    Content(#[from] rss_mdm_content_service::Error),
    #[error(transparent)]
    Inventory(#[from] rss_mdm_inventory_service::Error),
}
impl From<rss_mdm_task_state::Error> for Error {
    fn from(e: rss_mdm_task_state::Error) -> Self {
        match e {
            rss_mdm_task_state::Error::Malformed => Self::Malformed,
            rss_mdm_task_state::Error::Conflict => Self::Conflict,
        }
    }
}

impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        match e {
            rss_mdm_audit_integration::Error::CommitUnknown => Self::CommitUnknown,
            rss_mdm_audit_integration::Error::RollbackFailed => Self::RollbackFailed,
            other => Self::Audit(std::sync::Arc::new(other)),
        }
    }
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        use rss_mdm_authorization_service::error::AuthorizationError as A;
        match e {
            A::Malformed => Self::Malformed,
            A::Unauthorized => Self::Unauthorized,
            A::Forbidden => Self::Forbidden,
            A::Corrupt => Self::Invariant,
        }
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as R;
        match e {
            R::Unsupported => Self::Unsupported,
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Conflict => Self::Conflict,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::ReadConflict | R::CursorInvalidated | R::EnrollmentPaused => Self::Conflict,
            R::NotFound => Self::NotFound,
            R::Corrupt | R::Configuration => Self::Invariant,
            R::Audit(e) => Self::Audit(e),
            R::Agent(_) => Self::Unauthorized,
            R::Storage
            | R::Deadline
            | R::RegistrationLimit
            | R::Capacity
            | R::Runtime
            | R::Retirement => Self::Unavailable,
        }
    }
}

impl From<rss_mdm_policy::Error> for Error {
    fn from(e: rss_mdm_policy::Error) -> Self {
        match e {
            rss_mdm_policy::Error::Malformed => Self::Malformed,
            rss_mdm_policy::Error::Conflict => Self::Conflict,
            rss_mdm_policy::Error::NotFound => Self::NotFound,
        }
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as Authorization;
        match error {
            Authorization::Malformed => Self::Malformed,
            Authorization::Unauthorized => Self::Unauthorized,
            Authorization::Forbidden => Self::Forbidden,
            Authorization::Conflict => Self::Conflict,
            Authorization::CommitUnknown => Self::CommitUnknown,
            Authorization::RollbackFailed => Self::RollbackFailed,
            Authorization::Corrupt | Authorization::Configuration => Self::Invariant,
            Authorization::Storage | Authorization::Deadline => Self::Unavailable,
            Authorization::Audit(e) => Self::Audit(e),
        }
    }
}
