use crate::{Failure, planning, resource_catalog};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid request")]
    Malformed,
    #[error(transparent)]
    Planning(#[from] planning::error::PlanningError),
    #[error(transparent)]
    Resource(#[from] resource_catalog::error::ResourceError),
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
            Self::NotFound
                | Self::Planning(planning::error::PlanningError::Missing(_))
                | Self::Resource(resource_catalog::error::ResourceError::Missing)
        )
    }
}
