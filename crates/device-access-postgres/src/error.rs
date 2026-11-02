#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration signing failed: {0}")]
    Signing(rss_mdm_task_trust::Error),
    #[error("device access capability is not enabled")]
    Unsupported,
    #[error("Agent lifecycle rejected: {0:?}")]
    Agent(rss_mdm_agent_wire::enroll::ErrorCode),
    #[error("invalid device access input")]
    Malformed,
    #[error("authentication proof expired")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("invalid persisted device access")]
    Corrupt,
    #[error("device access storage unavailable")]
    Storage,
    #[error("device access deadline exceeded")]
    Deadline,
    #[error("device access operation conflict")]
    Conflict,
    #[error("read authority changed during the request")]
    ReadConflict,
    #[error("query continuation does not match the current context")]
    CursorInvalidated,
    #[error("device access commit outcome unknown")]
    CommitUnknown,
    #[error("device access rollback not acknowledged")]
    RollbackFailed,
    #[error("device access not found")]
    NotFound,
    #[error("self-service device access quota reached")]
    RegistrationLimit,
    #[error("new device access is paused")]
    EnrollmentPaused,
    #[error("credential handoff capacity reached")]
    Capacity,
    #[error("credential handoff unavailable")]
    Runtime,
    #[error("device access retirement failed")]
    Retirement,
    #[error("invalid device access configuration")]
    Configuration,
    #[error("device access audit failed")]
    Audit(std::sync::Arc<rss_mdm_audit_integration::Error>),
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(error: rss_mdm_audit_integration::Error) -> Self {
        match error {
            rss_mdm_audit_integration::Error::CommitUnknown => Self::CommitUnknown,
            rss_mdm_audit_integration::Error::RollbackFailed => Self::RollbackFailed,
            other => Self::Audit(std::sync::Arc::new(other)),
        }
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(error: rss_mdm_audit_integration::InvalidFact) -> Self {
        rss_mdm_audit_integration::Error::Fact(error).into()
    }
}

impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as Auth;
        match error {
            Auth::Malformed => Self::Malformed,
            Auth::Unauthorized => Self::Unauthorized,
            Auth::Forbidden => Self::Forbidden,
            Auth::Corrupt => Self::Corrupt,
            Auth::Storage => Self::Storage,
            Auth::Deadline => Self::Deadline,
            Auth::Conflict => Self::Conflict,
            Auth::CommitUnknown => Self::CommitUnknown,
            Auth::RollbackFailed => Self::RollbackFailed,
            Auth::Configuration => Self::Configuration,
            Auth::Audit(error) => Self::Audit(error),
        }
    }
}

impl From<rss_mdm_device_access::Error> for Error {
    fn from(_: rss_mdm_device_access::Error) -> Self {
        Self::Malformed
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
            R::Corrupt => Self::Corrupt,
            R::Storage => Self::Storage,
            R::Deadline => Self::Deadline,
            R::Conflict => Self::Conflict,
            R::ReadConflict => Self::ReadConflict,
            R::CursorInvalidated => Self::CursorInvalidated,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::NotFound => Self::NotFound,
            R::RegistrationLimit => Self::RegistrationLimit,
            R::EnrollmentPaused => Self::EnrollmentPaused,
            R::Capacity => Self::Capacity,
            R::Runtime => Self::Runtime,
            R::Retirement => Self::Retirement,
            R::Configuration => Self::Configuration,
            R::Agent(v) => Self::Agent(v),
            R::Audit(v) => Self::Audit(v),
        }
    }
}

impl From<rss_mdm_registration_service::participants::Error> for Error {
    fn from(e: rss_mdm_registration_service::participants::Error) -> Self {
        use rss_mdm_registration_service::participants::Error as P;
        match e {
            P::Malformed => Self::Malformed,
            P::Unauthorized => Self::Unauthorized,
            P::Forbidden => Self::Forbidden,
            P::Conflict => Self::Conflict,
            P::Unavailable => Self::Storage,
            P::CommitUnknown => Self::CommitUnknown,
            P::RollbackFailed => Self::RollbackFailed,
        }
    }
}

impl From<rss_mdm_task_trust::Error> for Error {
    fn from(value: rss_mdm_task_trust::Error) -> Self {
        use rss_mdm_task_trust::Error as E;
        match value {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::NotFound => Self::NotFound,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Unsupported => Self::Unsupported,
            E::ReadConflict => Self::ReadConflict,
            E::CursorInvalidated => Self::CursorInvalidated,
            other => Self::Signing(other),
        }
    }
}

impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        rss_mdm_authorization_service::Error::from(e).into()
    }
}
