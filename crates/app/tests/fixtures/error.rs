//! Fixture HTTP projection uses the production management boundary.
use axum::response::{IntoResponse, Response};
impl IntoResponse for crate::Error {
    fn into_response(self) -> Response {
        use rss_mdm_management_http::Error as H;
        let error = match self {
            Self::Flow(e) => H::from(e),
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
