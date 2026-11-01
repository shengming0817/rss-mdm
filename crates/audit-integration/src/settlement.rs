//! Project a completed original RSS attempt into request diagnostics without executing a transaction.
use crate::RequestAudit;
use rss_transactional_messaging::transaction::LocalTxAttempt;

impl RequestAudit {
    /// Preserve all six provider outcomes and their payloads. Business error mapping stays with the owner.
    pub fn observe_attempt<T, E>(&self, attempt: LocalTxAttempt<T, E>) -> LocalTxAttempt<T, E> {
        attempt.fold(
            |value| {
                self.mark_committed();
                LocalTxAttempt::committed(value)
            },
            LocalTxAttempt::not_started,
            |error| {
                self.mark_rolled_back();
                LocalTxAttempt::rolled_back(error)
            },
            |error| {
                self.mark_rollback_failed();
                LocalTxAttempt::rollback_failed(error)
            },
            |error| {
                self.mark_commit_started();
                LocalTxAttempt::commit_unknown(error)
            },
            LocalTxAttempt::fenced,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditIntent, WriteOutcome};
    #[test]
    fn original_outcomes_and_payloads_survive_diagnostic_projection() {
        let cases = [
            (LocalTxAttempt::committed(41), WriteOutcome::Committed),
            (
                LocalTxAttempt::not_started(41),
                WriteOutcome::CommitNotStarted,
            ),
            (LocalTxAttempt::rolled_back(41), WriteOutcome::RolledBack),
            (
                LocalTxAttempt::rollback_failed(41),
                WriteOutcome::RollbackFailed,
            ),
            (LocalTxAttempt::commit_unknown(41), WriteOutcome::Unknown),
            (LocalTxAttempt::fenced(41), WriteOutcome::CommitNotStarted),
        ];
        for (index, (attempt, expected)) in cases.into_iter().enumerate() {
            let audit = RequestAudit::new(
                crate::StorageProfile::Mdm,
                "tenant".into(),
                "recovery",
                AuditIntent::Management,
            );
            if index == 0 {
                audit.mark_commit_started();
            }
            let retained = audit.observe_attempt(attempt).fold(
                |v| (0, v),
                |e| (1, e),
                |e| (2, e),
                |e| (3, e),
                |e| (4, e),
                |e| (5, e),
            );
            assert_eq!(retained, (index, 41));
            assert_eq!(audit.snapshot().write_outcome, expected);
            audit.finalize(None);
        }
    }
}
