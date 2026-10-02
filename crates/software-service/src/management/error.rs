use super::publication::error::PublicationError;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed software management request")]
    Malformed,
    #[error("software management permission denied")]
    Forbidden,
    #[error("software management conflict")]
    Conflict,
    #[error("software management operation unsupported")]
    Unsupported,
    #[error("software resource unavailable")]
    ResourceMissing,
    #[error(transparent)]
    Publication(#[from] PublicationError),
    #[error("software management commit unconfirmed")]
    CommitUnknown,
    #[error("software management rollback unconfirmed")]
    RollbackFailed,
    #[error("software management unavailable: {0:?}")]
    Unavailable(Failure),
    #[error(transparent)]
    Authorization(#[from] rss_mdm_authorization_service::Error),
    #[error(transparent)]
    Audit(Box<rss_mdm_audit_integration::Error>),
}
#[derive(Clone, Copy, Debug)]
pub enum Failure {
    SoftwareCatalogStorage,
    SoftwareCatalogInvariant,
    PublicationStorage,
    Clock,
    Runtime,
    ContentStorage,
    ContentInvariant,
    ContentMetadata,
    ContentDeadline,
    ContentCleanup,
    ContentConfiguration,
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        Self::Authorization(e.into())
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        Self::Audit(Box::new(e))
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        rss_mdm_audit_integration::Error::Fact(e).into()
    }
}
impl Error {
    pub(crate) fn is_audit_transaction_failure(&self) -> bool {
        use rss_mdm_audit_integration::Error as A;
        let Self::Audit(error) = self else {
            return false;
        };
        let A::Audit(error) = error.as_ref() else {
            return false;
        };
        // Audit owns its underlying classification; interrupted operations are deadlines.
        if error.is_interrupted() {
            return false;
        }
        use rss_audit_postgres::Error as P;
        match error {
            P::Admission(_)
            | P::Conflict
            | P::StorageContract
            | P::IntegrityRequired
            | P::InvalidBound
            | P::ScopeMismatch
            | P::Protocol(_)
            | P::ReadBudgetExceeded => false,
            P::Ledger(e) => matches!(
                e,
                rss_ledger_postgres::Error::Storage(_) | rss_ledger_postgres::Error::Messaging(_)
            ),
            _ => true,
        }
    }
}
