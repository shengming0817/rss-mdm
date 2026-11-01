#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid credential request")]
    Malformed,
    #[error("credential unavailable for this target")]
    Unsupported,
    #[error("credential execution conflict")]
    Conflict,
    #[error("permission denied")]
    Forbidden,
    #[error("identity rejected")]
    Unauthorized,
    #[error("credential execution not found")]
    NotFound,
    #[error("credential storage invariant violated")]
    Invariant,
    #[error("credential dependency unavailable")]
    Unavailable,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("rollback not acknowledged; original attempt remains unresolved")]
    RollbackFailed,
    #[error(transparent)]
    Audit(#[from] std::sync::Arc<rss_mdm_audit_integration::Error>),
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
impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        use crate::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::NotFound => Self::NotFound,
            E::Conflict | E::ReadConflict | E::CursorInvalidated => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Integrity | E::Configuration => Self::Invariant,
            E::Unsupported => Self::Unsupported,
            _ => Self::Unavailable,
        }
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self::from(crate::Error::from(e))
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
