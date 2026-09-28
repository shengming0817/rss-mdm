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

/// Independent request settlement cannot overwrite the protected operation's certainty.
pub(crate) fn audit_settlement(
    original: Option<&Error>,
    outcome: rss_mdm_audit_integration::WriteOutcome,
    failure: Error,
) -> Error {
    match original {
        Some(Error::CommitUnknown) => Error::CommitUnknown,
        Some(Error::RollbackFailed) => Error::RollbackFailed,
        _ => match outcome {
            rss_mdm_audit_integration::WriteOutcome::Unknown
            | rss_mdm_audit_integration::WriteOutcome::Committed => Error::CommitUnknown,
            rss_mdm_audit_integration::WriteOutcome::RollbackFailed => Error::RollbackFailed,
            _ => failure,
        },
    }
}

/// Diagnostic cause is independent of the protected operation's settlement state.
pub(crate) fn audit_failure_reason(error: &Error) -> rss_mdm_audit_integration::FailureReason {
    use rss_mdm_audit_integration::FailureReason as Reason;
    match error {
        Error::Unavailable(crate::Failure::AuditIntegrity) => Reason::Integrity,
        Error::Unavailable(
            crate::Failure::AuditIsolation
            | crate::Failure::AuditContract
            | crate::Failure::AuditAdmission,
        ) => Reason::Contract,
        Error::Unavailable(crate::Failure::RequestDeadline) => Reason::Interrupted,
        _ => Reason::Persistent,
    }
}

#[cfg(test)]
#[path = "../tests/error_projection/unit.rs"]
mod tests;
