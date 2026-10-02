#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Group(#[from] crate::groups::GroupMissing),
    #[error("invalid inventory input")]
    Malformed,
    #[error("inventory source rejected")]
    Unauthorized,
    #[error("inventory access denied")]
    Forbidden,
    #[error("inventory conflict")]
    Conflict,
    #[error("inventory object not found")]
    NotFound,
    #[error("inventory commit outcome unknown")]
    CommitUnknown,
    #[error("inventory rollback unconfirmed")]
    RollbackFailed,
    #[error("inventory dependency unavailable: {0:?}")]
    Unavailable(Failure),
    #[error("inventory audit failure")]
    Audit(std::sync::Arc<rss_mdm_audit_integration::Error>),
}
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    AssetBytesLimit,
    AssetCandidates,
    AssetObjectLimit,
    AssetSourceLimit,
    AssetSources,
    AssetsStorage,
    Clock,
    CollectionQuery,
    ComplianceStorage,
    FlowStorage,
    InventoryQuery,
    ManualQuery,
    Runtime,
    Database,
    Protocol,
    Capacity,
    InventoryRuntime,
    RequestDeadline,
    Audit,
    AuditIntegrity,
    AuditAdmission,
    AuditIsolation,
    AuditContract,
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        match e {
            rss_mdm_audit_integration::Error::CommitUnknown => Self::CommitUnknown,
            rss_mdm_audit_integration::Error::RollbackFailed => Self::RollbackFailed,
            other => Self::Audit(std::sync::Arc::new(other)),
        }
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        rss_mdm_audit_integration::Error::Fact(e).into()
    }
}
impl From<crate::collection::CollectionError> for Error {
    fn from(_: crate::collection::CollectionError) -> Self {
        Self::Conflict
    }
}
impl From<rss_mdm_registration_service::device::DeviceError> for Error {
    fn from(_: rss_mdm_registration_service::device::DeviceError) -> Self {
        Self::Malformed
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as R;
        match e {
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Conflict => Self::Conflict,
            R::NotFound => Self::NotFound,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::Audit(e) => Self::Audit(e),
            R::Deadline => Self::Unavailable(Failure::RequestDeadline),
            R::Capacity => Self::Unavailable(Failure::Capacity),
            _ => Self::Unavailable(Failure::Database),
        }
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        rss_mdm_registration_service::Error::from(e).into()
    }
}

impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        rss_mdm_authorization_service::Error::from(e).into()
    }
}
