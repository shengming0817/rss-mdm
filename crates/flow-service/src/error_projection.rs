//! Execution failures observed by the remaining source scanner.
use crate::{Error, Failure};
impl From<rss_mdm_execution_service::Error> for Error {
    fn from(e: rss_mdm_execution_service::Error) -> Self {
        use rss_mdm_execution_service::Error as E;
        match e {
            E::MdmSoftwareDisabled => Self::MdmSoftwareDisabled,
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::ReadConflict
            | E::CursorInvalidated
            | E::Conflict
            | E::EnrollmentPaused
            | E::WindowsDeclaredEnrollmentNotReady => Self::Conflict,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Unsupported => Self::Unsupported,
            E::NotFound | E::Resource(_) => Self::ResourceMissing,
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
