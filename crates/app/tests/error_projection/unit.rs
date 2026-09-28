use super::*;
use rss_mdm_audit_integration::WriteOutcome::*;
#[test]
fn audit_and_ledger_interruptions_share_the_host_deadline_projection() {
    use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;
    for cause in [
        rss_audit_postgres::Error::Deadline(Stage::Operation),
        rss_audit_postgres::Error::Cancelled(Stage::Operation),
        rss_audit_postgres::Error::Ledger(rss_ledger_postgres::Error::Deadline(Stage::Operation)),
        rss_audit_postgres::Error::Ledger(rss_ledger_postgres::Error::Cancelled(Stage::Operation)),
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
            rss_mdm_audit_integration::Error::Fact(rss_mdm_audit_integration::InvalidFact::Actor),
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
