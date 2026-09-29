//! Content use-case failures retain storage and audit settlement certainty.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Content(#[from] crate::Error),
    #[error(transparent)]
    Authorization(#[from] rss_mdm_authorization_service::Error),
    #[error("content audit unavailable")]
    Audit(std::sync::Arc<rss_mdm_audit_integration::Error>),
    #[error("invalid content request")]
    Malformed,
    #[error("content operation conflict")]
    Conflict,
    #[error("content access denied")]
    Forbidden,
    #[error("content binding not found")]
    Missing,
    #[error("content capability disabled")]
    Unsupported,
    #[error("wall clock unavailable")]
    Clock,
    #[error("content import unavailable")]
    Import,
    #[error("content persistence unavailable")]
    Storage,
    #[error("content persistence invariant violated")]
    Invariant,
    #[error("content commit outcome unknown")]
    CommitUnknown,
    #[error("content rollback not acknowledged")]
    RollbackFailed,
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        Self::Authorization(e.into())
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        match e {
            rss_mdm_audit_integration::Error::CommitUnknown => Self::CommitUnknown,
            rss_mdm_audit_integration::Error::RollbackFailed => Self::RollbackFailed,
            e => Self::Audit(std::sync::Arc::new(e)),
        }
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        rss_mdm_audit_integration::Error::Fact(e).into()
    }
}
