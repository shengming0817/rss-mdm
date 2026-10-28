use crate::Failure;
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid scope request")]
    Malformed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("scope changed")]
    Conflict,
    #[error("scope not found")]
    NotFound,
    #[error("unsupported scope source")]
    Unsupported,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("rollback unacknowledged")]
    RollbackFailed,
    #[error("scope dependency unavailable")]
    Unavailable(Failure),
}
impl Error {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }
}
