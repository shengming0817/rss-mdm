use super::*;
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
async fn durable_corruption_is_distinct_from_interruption() {
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
        let diagnostic =
            crate::diagnostic::ProcessError::at("startup.audit", projected.clone()).to_string();
        assert!(diagnostic.contains("Audit"));
        let response = projected.into_response();
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
}
