//! One-way domain-to-host projection. HTTP codes remain owned by the host error boundary.
use crate::{Error, Failure};
impl From<crate::authorization::error::AuthorizationError> for Error {
    fn from(error: crate::authorization::error::AuthorizationError) -> Self {
        use crate::authorization::error::AuthorizationError as Domain;
        match error {
            Domain::Malformed => Self::Malformed,
            Domain::Unauthorized => Self::Unauthorized,
            Domain::Forbidden => Self::Forbidden,
            Domain::Corrupt => Self::Unavailable(crate::Failure::Database),
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
        use rss_mdm_audit_integration::ErrorClass as C;
        match error.class() {
            C::CommitUnknown => Self::CommitUnknown,
            C::RollbackFailed => Self::RollbackFailed,
            C::RequestDeadline => Self::Unavailable(Failure::RequestDeadline),
            C::AuditIntegrity => Self::Unavailable(Failure::AuditIntegrity),
            C::AuditAdmission => Self::Unavailable(Failure::AuditAdmission),
            C::AuditIsolation => Self::Unavailable(Failure::AuditIsolation),
            C::AuditContract => Self::Unavailable(Failure::AuditContract),
            C::Audit => Self::Unavailable(Failure::Audit),
        }
    }
}

impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as Authorization;
        match error {
            Authorization::Malformed => Self::Malformed,
            Authorization::Unauthorized => Self::Unauthorized,
            Authorization::Forbidden => Self::Forbidden,
            Authorization::Corrupt | Authorization::Storage => {
                Self::Unavailable(crate::Failure::Database)
            }
            Authorization::Deadline => Self::Unavailable(crate::Failure::RequestDeadline),
            Authorization::Conflict => Self::Conflict,
            Authorization::CommitUnknown => Self::CommitUnknown,
            Authorization::RollbackFailed => Self::RollbackFailed,
            Authorization::Configuration => Self::Unavailable(Failure::Database),
            Authorization::Audit(error) => Self::from(error.as_ref()),
        }
    }
}

impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        use rss_mdm_inventory_service::Error as I;
        match e {
            I::Group(m) => {
                Self::Planning(crate::planning::error::PlanningError::Missing(match m {
                    rss_mdm_inventory_service::groups::GroupMissing::Group => {
                        crate::planning::error::Missing::Group
                    }
                    rss_mdm_inventory_service::groups::GroupMissing::Rule => {
                        crate::planning::error::Missing::Rule
                    }
                    rss_mdm_inventory_service::groups::GroupMissing::Device => {
                        crate::planning::error::Missing::Device
                    }
                }))
            }
            I::Malformed => Self::Malformed,
            I::Unauthorized => Self::Unauthorized,
            I::Forbidden => Self::Forbidden,
            I::Conflict => Self::Conflict,
            I::NotFound => Self::NotFound,
            I::CommitUnknown => Self::CommitUnknown,
            I::RollbackFailed => Self::RollbackFailed,
            I::Audit(e) => Self::from(e.as_ref()),
            I::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_inventory_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_inventory_service::Failure::Audit => Failure::Audit,
                rss_mdm_inventory_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_inventory_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_inventory_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_inventory_service::Failure::AuditContract => Failure::AuditContract,
                other => Failure::Inventory(other),
            }),
        }
    }
}

impl From<rss_mdm_content_service::Error> for Error {
    fn from(e: rss_mdm_content_service::Error) -> Self {
        match e {
            rss_mdm_content_service::Error::Malformed => Self::Malformed,
            rss_mdm_content_service::Error::Conflict => Self::Conflict,
            other => Self::Unavailable(Failure::ResourceContent(other)),
        }
    }
}
impl From<rss_mdm_execution_service::Error> for Error {
    fn from(e: rss_mdm_execution_service::Error) -> Self {
        use rss_mdm_execution_service::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict | E::WindowsDeclaredEnrollmentNotReady => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Unsupported => Self::Unsupported,
            E::NotFound | E::Resource(_) => {
                Self::Resource(crate::resource_catalog::error::ResourceError::Missing)
            }
            E::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_execution_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_execution_service::Failure::Audit => Failure::Audit,
                rss_mdm_execution_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_execution_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_execution_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_execution_service::Failure::AuditContract => Failure::AuditContract,
                other => Failure::Preparation(other),
            }),
            E::Configuration(c) => Self::Unavailable(Failure::PreparationConfiguration(c)),
            E::Execution(_) | E::Publication(_) | E::CertificateRequest => {
                Self::Unavailable(Failure::PreparationContract)
            }
        }
    }
}
