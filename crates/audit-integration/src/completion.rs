//! Request audit completion is transport-neutral; each ingress projects its own wire response.
use crate::{AuditStore, Error, FailureReason, ManagementResult, RequestAudit, WriteOutcome};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseFailure {
    CommitUnknown,
    RollbackFailed,
    Deadline,
    Denied,
    AuditIntegrity,
    AuditContract,
    AuditUnavailable,
}
pub enum Replacement {
    CommitUnknown,
    RollbackFailed,
    Audit(Error),
}
fn protected_result(
    failure: Option<ResponseFailure>,
    outcome: WriteOutcome,
) -> Option<Replacement> {
    match failure {
        Some(ResponseFailure::CommitUnknown) => Some(Replacement::CommitUnknown),
        Some(ResponseFailure::RollbackFailed) => Some(Replacement::RollbackFailed),
        _ => match outcome {
            WriteOutcome::Unknown | WriteOutcome::Committed => Some(Replacement::CommitUnknown),
            WriteOutcome::RollbackFailed => Some(Replacement::RollbackFailed),
            _ => None,
        },
    }
}
pub async fn complete(
    store: &AuditStore,
    audit: &RequestAudit,
    status: u16,
    failure: Option<ResponseFailure>,
) -> Option<Replacement> {
    let snapshot = audit.snapshot();
    let mut replacement = if failure == Some(ResponseFailure::Deadline) {
        protected_result(failure, snapshot.write_outcome)
    } else {
        None
    };
    let mut reason = match failure {
        Some(ResponseFailure::AuditIntegrity) => Some(FailureReason::Integrity),
        Some(ResponseFailure::AuditContract) => Some(FailureReason::Contract),
        Some(ResponseFailure::AuditUnavailable) => Some(FailureReason::Transaction),
        _ => None,
    };
    if snapshot.settle_request
        || snapshot.write_outcome != WriteOutcome::Committed
        || matches!(snapshot.management_result, Some(ManagementResult::Replayed))
    {
        let unknown = replacement.is_some()
            || matches!(
                failure,
                Some(ResponseFailure::CommitUnknown | ResponseFailure::RollbackFailed)
            )
            || snapshot.write_outcome == WriteOutcome::Unknown && status >= 500;
        let result = request_result(status, failure, &snapshot, unknown);
        let budget = crate::budget::AuditBudget::new(std::time::Duration::from_secs(2));
        if let Err(error) = store
            .settle_request(audit, status, result, &budget.control())
            .await
        {
            reason = Some(failure_reason(&error));
            replacement = protected_result(failure, snapshot.write_outcome)
                .or(Some(Replacement::Audit(error)));
        }
    }
    audit.finalize(reason);
    replacement
}
fn request_result(
    status: u16,
    failure: Option<ResponseFailure>,
    snapshot: &crate::Snapshot,
    unknown: bool,
) -> &'static str {
    if unknown {
        "unknown"
    } else if status == 401 || status == 403 || failure == Some(ResponseFailure::Denied) {
        "denied"
    } else if status >= 400 {
        "failed"
    } else {
        snapshot
            .management_result
            .map_or("success", |r| r.audit_tag())
    }
}
fn failure_reason(error: &Error) -> FailureReason {
    use rss_audit_postgres::Error as Audit;
    match error {
        Error::Receipt => FailureReason::Integrity,
        Error::Isolation | Error::Admission | Error::Fact(_) => FailureReason::Contract,
        Error::Audit(error) if error.is_interrupted() => FailureReason::Interrupted,
        Error::Audit(
            Audit::Admission(_)
            | Audit::InvalidBound
            | Audit::ScopeMismatch
            | Audit::Protocol(_)
            | Audit::ReadBudgetExceeded,
        ) => FailureReason::Contract,
        Error::Audit(Audit::Conflict | Audit::StorageContract | Audit::IntegrityRequired) => {
            FailureReason::Integrity
        }
        Error::Audit(Audit::Ledger(error)) => match error {
            rss_ledger_postgres::Error::Storage(_) | rss_ledger_postgres::Error::Messaging(_) => {
                FailureReason::Persistent
            }
            rss_ledger_postgres::Error::Admission(_) => FailureReason::Contract,
            _ => FailureReason::Integrity,
        },
        _ => FailureReason::Persistent,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_settlement_preserves_original_commit_and_rollback_uncertainty() {
        for outcome in [
            WriteOutcome::CommitNotStarted,
            WriteOutcome::RolledBack,
            WriteOutcome::Unknown,
            WriteOutcome::Committed,
            WriteOutcome::RollbackFailed,
        ] {
            assert!(matches!(
                protected_result(Some(ResponseFailure::CommitUnknown), outcome),
                Some(Replacement::CommitUnknown)
            ));
            assert!(matches!(
                protected_result(Some(ResponseFailure::RollbackFailed), outcome),
                Some(Replacement::RollbackFailed)
            ));
        }
        assert!(protected_result(None, WriteOutcome::CommitNotStarted).is_none());
        assert!(protected_result(None, WriteOutcome::RolledBack).is_none());
        assert!(matches!(
            protected_result(None, WriteOutcome::Committed),
            Some(Replacement::CommitUnknown)
        ));
        assert!(matches!(
            protected_result(None, WriteOutcome::Unknown),
            Some(Replacement::CommitUnknown)
        ));
        assert!(matches!(
            protected_result(None, WriteOutcome::RollbackFailed),
            Some(Replacement::RollbackFailed)
        ));
    }
    #[test]
    fn operation_coordinate_does_not_claim_request_replay() {
        let audit = RequestAudit::new(
            "11111111-1111-4111-8111-111111111111".into(),
            "command_read",
        );
        audit.operation(uuid::Uuid::new_v4(), "command_read");
        assert_eq!(
            request_result(200, None, &audit.snapshot(), false),
            "success"
        );
        audit.management_result(ManagementResult::Replayed);
        assert_eq!(
            request_result(200, None, &audit.snapshot(), false),
            "replay"
        );
        audit.finalize(None);
    }
}
