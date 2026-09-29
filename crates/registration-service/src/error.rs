#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid registration input")]
    Malformed,
    #[error("authentication proof expired")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("invalid persisted registration")]
    Corrupt,
    #[error("registration storage unavailable")]
    Storage,
    #[error("registration deadline exceeded")]
    Deadline,
    #[error("registration operation conflict")]
    Conflict,
    #[error("registration commit outcome unknown")]
    CommitUnknown,
    #[error("registration rollback not acknowledged")]
    RollbackFailed,
    #[error("registration not found")]
    NotFound,
    #[error("credential handoff capacity reached")]
    Capacity,
    #[error("credential handoff unavailable")]
    Runtime,
    #[error("registration retirement failed")]
    Retirement,
    #[error("invalid registration configuration")]
    Configuration,
    #[error("registration audit failed")]
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
impl From<crate::enrollment::EnrollmentError> for Error {
    fn from(_: crate::enrollment::EnrollmentError) -> Self {
        Self::Malformed
    }
}
impl From<crate::device::DeviceError> for Error {
    fn from(_: crate::device::DeviceError) -> Self {
        Self::Malformed
    }
}
