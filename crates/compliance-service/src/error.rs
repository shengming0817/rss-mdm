#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid compliance input")]
    Malformed,
    #[error("compliance source rejected")]
    Unauthorized,
    #[error("compliance access denied")]
    Forbidden,
    #[error("compliance conflict")]
    Conflict,
    #[error("compliance object not found")]
    NotFound,
    #[error("compliance commit outcome unknown")]
    CommitUnknown,
    #[error("compliance rollback unconfirmed")]
    RollbackFailed,
    #[error("compliance dependency unavailable: {0:?}")]
    Unavailable(Failure),
    #[error("compliance audit failure")]
    Audit(std::sync::Arc<rss_mdm_audit_integration::Error>),
}
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    AssetBytesLimit,
    AssetObjectLimit,
    AssetSourceLimit,
    AssetsStorage,
    Capacity,
    Clock,
    ComplianceStorage,
    Database,
    PlanningStorage,
    RequestDeadline,
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
impl From<rss_mdm_registration_service::device::DeviceError> for Error {
    fn from(_: rss_mdm_registration_service::device::DeviceError) -> Self {
        Self::Malformed
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as R;
        match e {
            R::Agent(_) => Self::Unauthorized,
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Conflict | R::EnrollmentPaused => Self::Conflict,
            R::NotFound => Self::NotFound,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::Audit(e) => Self::Audit(e),
            R::Deadline => Self::Unavailable(Failure::RequestDeadline),
            R::Capacity | R::RegistrationLimit => Self::Unavailable(Failure::Capacity),
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

impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(value: rss_mdm_inventory_service::Error) -> Self {
        use rss_mdm_inventory_service::{Error as E, Failure as F};
        match value {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict | E::Referenced => Self::Conflict,
            E::NotFound => Self::NotFound,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Audit(e) => Self::Audit(e),
            E::Unavailable(F::AssetSourceLimit) => Self::Unavailable(Failure::AssetSourceLimit),
            E::Unavailable(F::AssetBytesLimit) => Self::Unavailable(Failure::AssetBytesLimit),
            E::Unavailable(F::AssetObjectLimit) => Self::Unavailable(Failure::AssetObjectLimit),
            E::Unavailable(F::Clock) => Self::Unavailable(Failure::Clock),
            E::Unavailable(_) => Self::Unavailable(Failure::AssetsStorage),
        }
    }
}
