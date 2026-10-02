use crate::{ConfigIssue, Failure};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid product configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error(transparent)]
    Resource(#[from] ResourceError),
    #[error(transparent)]
    Execution(#[from] crate::missing::ExecutionError),
    #[error(transparent)]
    Publication(#[from] rss_mdm_software_service::management::publication::error::PublicationError),
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("operation identity or enrollment/registration state conflict")]
    Conflict,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("rollback not acknowledged; original attempt remains unresolved")]
    RollbackFailed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("inventory not found")]
    NotFound,
    #[error("action not supported")]
    Unsupported,
}
impl Error {
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::NotFound | Self::Resource(_) | Self::Execution(_) | Self::Publication(_)
        )
    }
}
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum ResourceError {
    #[error("resource_not_found")]
    Missing,
}
