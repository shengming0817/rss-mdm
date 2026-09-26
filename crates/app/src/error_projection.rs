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
            Error::Unavailable(crate::Failure::AuditIntegrity)
        ));
    }
    #[tokio::test]
    async fn durable_corruption_is_distinct_from_interruption_and_preserves_settlement() {
        use axum::response::IntoResponse;
        for (cause, reason) in [
            (
                rss_mdm_audit_integration::Error::Receipt,
                "audit_integrity_error",
            ),
            (
                rss_mdm_audit_integration::Error::Isolation,
                "audit_contract_error",
            ),
            (
                rss_mdm_audit_integration::Error::Fact(
                    rss_mdm_audit_integration::InvalidFact::Actor,
                ),
                "audit_contract_error",
            ),
        ] {
            let projected = Error::from(cause);
            assert_eq!(
                serde_json::to_value(audit_failure_reason(&projected)).unwrap(),
                reason
            );
            let settled = audit_settlement(None, RolledBack, projected);
            let diagnostic =
                crate::diagnostic::ProcessError::at("startup.audit", settled.clone()).to_string();
            assert!(diagnostic.contains("Audit"));
            let response = settled.into_response();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            );
            assert!(matches!(
                response.extensions().get::<Error>(),
                Some(Error::Unavailable(_))
            ));
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["code"], reason);
        }
        let unknown = audit_settlement(
            Some(&Error::CommitUnknown),
            RolledBack,
            Error::Unavailable(crate::Failure::AuditIntegrity),
        );
        assert!(matches!(unknown, Error::CommitUnknown));
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
                audit_settlement(
                    Some(&Error::CommitUnknown),
                    state,
                    Error::Unavailable(crate::Failure::Audit)
                ),
                Error::CommitUnknown
            ));
            assert!(matches!(
                audit_settlement(
                    Some(&Error::RollbackFailed),
                    state,
                    Error::Unavailable(crate::Failure::Audit)
                ),
                Error::RollbackFailed
            ));
        }
        for state in [Unknown, Committed] {
            assert!(matches!(
                audit_settlement(None, state, Error::Unavailable(crate::Failure::Audit)),
                Error::CommitUnknown
            ));
        }
        assert!(matches!(
            audit_settlement(
                None,
                RollbackFailed,
                Error::Unavailable(crate::Failure::Audit)
            ),
            Error::RollbackFailed
        ));
        for state in [CommitNotStarted, RolledBack] {
            assert!(matches!(
                audit_settlement(
                    Some(&Error::Forbidden),
                    state,
                    Error::Unavailable(crate::Failure::Audit)
                ),
                Error::Unavailable(crate::Failure::Audit)
            ));
        }
    }
}
