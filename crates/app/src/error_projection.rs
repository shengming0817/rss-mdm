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
            rss_mdm_audit_integration::Error::Audit(error) if error.is_interrupted() => {
                Self::Unavailable(crate::Failure::RequestDeadline)
            }
            _ => Self::Unavailable(crate::Failure::Audit),
        }
    }
}

/// Independent request settlement cannot overwrite the protected operation's certainty.
pub(crate) fn audit_settlement(
    original: Option<&Error>,
    outcome: rss_mdm_audit_integration::WriteOutcome,
) -> Error {
    match original {
        Some(Error::CommitUnknown) => Error::CommitUnknown,
        Some(Error::RollbackFailed) => Error::RollbackFailed,
        _ => match outcome {
            rss_mdm_audit_integration::WriteOutcome::Unknown
            | rss_mdm_audit_integration::WriteOutcome::Committed => Error::CommitUnknown,
            rss_mdm_audit_integration::WriteOutcome::RollbackFailed => Error::RollbackFailed,
            _ => Error::Unavailable(crate::Failure::Audit),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_mdm_audit_integration::WriteOutcome::*;
    #[test]
    fn audit_and_ledger_interruptions_share_the_host_deadline_projection() {
        use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;
        for cause in [
            rss_audit_postgres::Error::Deadline(Stage::Operation),
            rss_audit_postgres::Error::Cancelled(Stage::Operation),
            rss_audit_postgres::Error::Ledger(rss_ledger_postgres::Error::Deadline(
                Stage::Operation,
            )),
            rss_audit_postgres::Error::Ledger(rss_ledger_postgres::Error::Cancelled(
                Stage::Operation,
            )),
        ] {
            assert!(matches!(
                Error::from(rss_mdm_audit_integration::Error::Audit(cause)),
                Error::Unavailable(crate::Failure::RequestDeadline)
            ));
        }
        assert!(matches!(
            Error::from(rss_mdm_audit_integration::Error::Audit(
                rss_audit_postgres::Error::Ledger(rss_ledger_postgres::Error::StorageContract)
            )),
            Error::Unavailable(crate::Failure::Audit)
        ));
    }
    #[test]
    fn request_settlement_preserves_business_certainty() {
        for state in [
            CommitNotStarted,
            RolledBack,
            Unknown,
            Committed,
            RollbackFailed,
        ] {
            assert!(matches!(
                audit_settlement(Some(&Error::CommitUnknown), state),
                Error::CommitUnknown
            ));
            assert!(matches!(
                audit_settlement(Some(&Error::RollbackFailed), state),
                Error::RollbackFailed
            ));
        }
        for state in [Unknown, Committed] {
            assert!(matches!(
                audit_settlement(None, state),
                Error::CommitUnknown
            ));
        }
        assert!(matches!(
            audit_settlement(None, RollbackFailed),
            Error::RollbackFailed
        ));
        for state in [CommitNotStarted, RolledBack] {
            assert!(matches!(
                audit_settlement(Some(&Error::Forbidden), state),
                Error::Unavailable(crate::Failure::Audit)
            ));
        }
    }
}
