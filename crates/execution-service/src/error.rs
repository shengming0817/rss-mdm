#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigIssue {
    TaskSigning,
    IdentityConfiguration,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    NativeProtection,
    CommandInvariant,
    Database,
    RequestDeadline,
    Audit,
    AuditIntegrity,
    AuditAdmission,
    AuditIsolation,
    AuditContract,
}
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid execution configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error("operation conflict")]
    Conflict,
    #[error("commit outcome unknown")]
    CommitUnknown,
    #[error("rollback not acknowledged")]
    RollbackFailed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("action not supported")]
    Unsupported,
    #[error("dependency unavailable")]
    Unavailable(Failure),
}

impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        use rss_mdm_authorization_service::error::AuthorizationError as A;
        match e {
            A::Malformed => Self::Malformed,
            A::Unauthorized => Self::Unauthorized,
            A::Forbidden => Self::Forbidden,
            A::Corrupt => Self::Unavailable(Failure::Database),
        }
    }
}

impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as A;
        match e {
            A::Malformed => Self::Malformed,
            A::Unauthorized => Self::Unauthorized,
            A::Forbidden => Self::Forbidden,
            A::Corrupt | A::Storage => Self::Unavailable(Failure::Database),
            A::Deadline => Self::Unavailable(Failure::RequestDeadline),
            A::Conflict => Self::Conflict,
            A::CommitUnknown => Self::CommitUnknown,
            A::RollbackFailed => Self::RollbackFailed,
            A::Configuration => Self::Configuration(ConfigIssue::IdentityConfiguration),
            A::Audit(e) => Self::from(e.as_ref()),
        }
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(error: rss_mdm_audit_integration::InvalidFact) -> Self {
        Self::from(rss_mdm_audit_integration::Error::Fact(error))
    }
}

impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(error: rss_mdm_audit_integration::Error) -> Self {
        Self::from(&error)
    }
}
impl From<&rss_mdm_audit_integration::Error> for Error {
    fn from(error: &rss_mdm_audit_integration::Error) -> Self {
        match error {
            rss_mdm_audit_integration::Error::CommitUnknown => Self::CommitUnknown,
            rss_mdm_audit_integration::Error::RollbackFailed => Self::RollbackFailed,
            rss_mdm_audit_integration::Error::Audit(error) if error.is_interrupted() => {
                Self::Unavailable(crate::Failure::RequestDeadline)
            }
            rss_mdm_audit_integration::Error::Receipt => {
                Self::Unavailable(crate::Failure::AuditIntegrity)
            }
            rss_mdm_audit_integration::Error::Admission => {
                Self::Unavailable(crate::Failure::AuditAdmission)
            }
            rss_mdm_audit_integration::Error::Isolation => {
                Self::Unavailable(crate::Failure::AuditIsolation)
            }
            rss_mdm_audit_integration::Error::Fact(_) => {
                Self::Unavailable(crate::Failure::AuditContract)
            }
            rss_mdm_audit_integration::Error::Audit(error) => {
                use rss_audit_postgres::Error as Audit;
                Self::Unavailable(match error {
                    Audit::Admission(_) => crate::Failure::AuditAdmission,
                    Audit::Conflict | Audit::StorageContract | Audit::IntegrityRequired => {
                        crate::Failure::AuditIntegrity
                    }
                    Audit::Ledger(error) => match error {
                        rss_ledger_postgres::Error::Storage(_)
                        | rss_ledger_postgres::Error::Messaging(_) => crate::Failure::Audit,
                        rss_ledger_postgres::Error::Admission(_) => crate::Failure::AuditAdmission,
                        _ => crate::Failure::AuditIntegrity,
                    },
                    Audit::InvalidBound
                    | Audit::ScopeMismatch
                    | Audit::Protocol(_)
                    | Audit::ReadBudgetExceeded => crate::Failure::AuditContract,
                    _ => crate::Failure::Audit,
                })
            }
        }
    }
}
