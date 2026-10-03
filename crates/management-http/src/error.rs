//! Closed HTTP request projection; domain errors are converted only at this ingress.
use crate::{ConfigIssue, Failure, planning, resource_catalog};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error(transparent)]
    Archive(#[from] rss_mdm_certificate_archive_service::Error),
    #[error("invalid product configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error(transparent)]
    Group(#[from] rss_mdm_inventory_service::groups::GroupMissing),
    #[error(transparent)]
    Planning(#[from] planning::error::PlanningError),
    #[error(transparent)]
    Resource(#[from] resource_catalog::error::ResourceError),
    #[error(transparent)]
    Execution(#[from] rss_mdm_execution_service::missing::ExecutionError),
    #[error(transparent)]
    Publication(#[from] rss_mdm_software_service::management::publication::error::PublicationError),
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("operation identity or enrollment/registration state conflict")]
    Conflict,
    #[error("Windows declared enrollment is not ready")]
    WindowsDeclaredEnrollmentNotReady,
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
            Self::NotFound
                | Self::Group(_)
                | Self::Planning(planning::error::PlanningError::Missing(_))
                | Self::Resource(resource_catalog::error::ResourceError::Missing)
                | Self::Execution(_)
                | Self::Publication(_)
        )
    }
}
