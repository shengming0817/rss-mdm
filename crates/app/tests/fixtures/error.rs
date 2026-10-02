//! Fixture HTTP projection uses the production management wire boundary.
use axum::response::{IntoResponse, Response};
impl IntoResponse for crate::Error {
    fn into_response(self) -> Response {
        match self {
            Self::Execution(e) => rss_mdm_management_http::Error(e.into()).into_response(),
            Self::Service(e) => rss_mdm_management_http::Error(e).into_response(),
            Self::Apple(e) => e.into_response(),
            Self::Windows(e) => e.into_response(),
            Self::Unavailable(f) => (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({"code":"service_unavailable","reason": f})),
            )
                .into_response(),
            Self::Configuration(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
}
