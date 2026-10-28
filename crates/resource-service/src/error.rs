#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum ResourceError {
    #[error("resource_not_found")]
    Missing,
}

#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid request")]
    Malformed,
    #[error("resource cursor invalidated")]
    ResourceCursorInvalidated,
    #[error(transparent)]
    Resource(#[from] ResourceError),
    #[error("resource conflict")]
    Conflict,
    #[error("commit outcome unknown")]
    CommitUnknown,
    #[error("rollback unconfirmed")]
    RollbackFailed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("unsupported resource")]
    Unsupported,
}
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    ResourceAdmission,
    ResourceStorage,
    ResourceSoftwareIntegrity,
    RequestDeadline,
    Database,
    Audit,
    AuditIntegrity,
    AuditIsolation,
    AuditContract,
    AuditAdmission,
    Clock,
}
