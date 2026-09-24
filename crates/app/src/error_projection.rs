//! One-way domain-to-host projection. HTTP codes remain owned by the host error boundary.
use crate::Error;
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
impl From<crate::enrollment::EnrollmentError> for Error {
    fn from(error: crate::enrollment::EnrollmentError) -> Self {
        match error {
            crate::enrollment::EnrollmentError::InvalidPassword => Self::Malformed,
        }
    }
}
impl From<crate::device::DeviceError> for Error {
    fn from(error: crate::device::DeviceError) -> Self {
        match error {
            crate::device::DeviceError::InvalidSource => Self::Malformed,
        }
    }
}
impl From<crate::collection::CollectionError> for Error {
    fn from(error: crate::collection::CollectionError) -> Self {
        match error {
            crate::collection::CollectionError::CorrelationConflict => Self::Conflict,
        }
    }
}
impl From<crate::management::assets::AssetError> for Error {
    fn from(error: crate::management::assets::AssetError) -> Self {
        match error {
            crate::management::assets::AssetError::RestrictedScope => Self::Forbidden,
        }
    }
}

pub(crate) fn audit_deadline(outcome: rss_mdm_audit_integration::WriteOutcome) -> crate::Error {
    match outcome {
        rss_mdm_audit_integration::WriteOutcome::Unknown
        | rss_mdm_audit_integration::WriteOutcome::Committed => crate::Error::CommitUnknown,
        rss_mdm_audit_integration::WriteOutcome::RollbackFailed => crate::Error::RollbackFailed,
        rss_mdm_audit_integration::WriteOutcome::RolledBack
        | rss_mdm_audit_integration::WriteOutcome::CommitNotStarted => {
            crate::Error::Unavailable(crate::Failure::RequestDeadline)
        }
    }
}

impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(error: rss_mdm_audit_integration::Error) -> Self {
        match error {
            rss_mdm_audit_integration::Error::CommitUnknown => Self::CommitUnknown,
            rss_mdm_audit_integration::Error::RollbackFailed => Self::RollbackFailed,
            _ => Self::Unavailable(crate::Failure::Audit),
        }
    }
}
