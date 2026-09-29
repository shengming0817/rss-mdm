#[derive(Clone, Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("invalid authorization input")]
    Malformed,
    #[error("authentication proof expired")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("invalid persisted authorization")]
    Corrupt,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid authorization input")]
    Malformed,
    #[error("authentication proof expired")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("invalid persisted authorization")]
    Corrupt,
    #[error("authorization storage unavailable")]
    Storage,
    #[error("authorization deadline exceeded")]
    Deadline,
    #[error("authorization operation conflict")]
    Conflict,
    #[error("authorization commit outcome unknown")]
    CommitUnknown,
    #[error("authorization rollback not acknowledged")]
    RollbackFailed,
    #[error("invalid authorization configuration")]
    Configuration,
    #[error("authorization audit failed")]
    Audit(std::sync::Arc<rss_mdm_audit_integration::Error>),
}
impl From<AuthorizationError> for Error {
    fn from(error: AuthorizationError) -> Self {
        match error {
            AuthorizationError::Malformed => Self::Malformed,
            AuthorizationError::Unauthorized => Self::Unauthorized,
            AuthorizationError::Forbidden => Self::Forbidden,
            AuthorizationError::Corrupt => Self::Corrupt,
        }
    }
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
