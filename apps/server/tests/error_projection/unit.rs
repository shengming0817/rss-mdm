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
            Error::Unavailable(Failure::RequestDeadline)
        ));
    }
    assert!(matches!(
        Error::from(rss_mdm_audit_integration::Error::Audit(
            rss_audit_postgres::Error::Ledger(rss_ledger_postgres::Error::StorageContract)
        )),
        Error::Unavailable(Failure::AuditIntegrity)
    ));
}
#[tokio::test]
async fn durable_corruption_is_distinct_from_interruption() {
    use axum::response::IntoResponse;
    for (cause, reason, category) in [
        (
            rss_mdm_audit_integration::Error::Receipt,
            "audit_integrity_error",
            Failure::AuditIntegrity,
        ),
        (
            rss_mdm_audit_integration::Error::Isolation,
            "audit_contract_error",
            Failure::AuditIsolation,
        ),
        (
            rss_mdm_audit_integration::Error::Fact(rss_mdm_audit_integration::InvalidFact::Actor),
            "audit_contract_error",
            Failure::AuditContract,
        ),
    ] {
        let projected = Error::from(&cause);
        let diagnostic =
            crate::diagnostic::ProcessError::at("startup.audit", Error::from(&cause)).to_string();
        assert_eq!(diagnostic, format!("startup.audit: {category:?}"));
        let response = projected.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(matches!(
            response
                .extensions()
                .get::<rss_mdm_management_http::Error>(),
            Some(rss_mdm_management_http::Error::Unavailable(_))
        ));
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], reason);
    }
}

use axum::response::{IntoResponse, Response};
impl IntoResponse for crate::Error {
    fn into_response(self) -> Response {
        use rss_mdm_management_http::Error as H;
        let error = match self {
            Self::Webhook(error) => error.into(),
            Self::NotFound => H::NotFound,
            Self::FirstUseNotReady => H::FirstUseNotReady,
            Self::FirstUseOperationMissing => H::FirstUseOperationMissing,
            Self::Scope(e) => H::from(e),
            Self::Resource(e) => e.into(),

            Self::Policy(e) => H::from(e),
            Self::Execution(e) => H::from(e),
            Self::Authorization(e) => H::from(e),
            Self::Registration(e) => H::from(e),
            Self::Inventory(e) => H::from(e),
            Self::Software(e) => H::from(e),
            Self::Content(e) => H::from(e),
            Self::ContentRequest(e) => H::from(e),
            Self::Http(e) => e,
            Self::Apple(e) => return e.into_response(),
            Self::Windows(e) => return e.into_response(),
            Self::CommitUnknown => H::CommitUnknown,
            Self::RollbackFailed => H::RollbackFailed,
            Self::Malformed => H::Malformed,
            Self::CertificateRequest => H::CertificateRequest,
            Self::Forbidden => H::Forbidden,
            Self::Unauthorized => H::Unauthorized,
            Self::Conflict => H::Conflict,
            Self::Unsupported => H::Unsupported,
            Self::Configuration(_) => H::Unavailable(rss_mdm_management_http::Failure::Runtime),
            Self::Unavailable(f) => H::Unavailable(match f {
                crate::Failure::RequestDeadline => {
                    rss_mdm_management_http::Failure::RequestDeadline
                }
                crate::Failure::AuditIntegrity => rss_mdm_management_http::Failure::AuditIntegrity,
                crate::Failure::AuditAdmission => rss_mdm_management_http::Failure::AuditAdmission,
                crate::Failure::AuditIsolation => rss_mdm_management_http::Failure::AuditIsolation,
                crate::Failure::AuditContract => rss_mdm_management_http::Failure::AuditContract,
                crate::Failure::Audit => rss_mdm_management_http::Failure::Audit,
                _ => rss_mdm_management_http::Failure::Runtime,
            }),
        };
        error.into_response()
    }
}
