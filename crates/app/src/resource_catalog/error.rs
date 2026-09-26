use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum ResourceError {
    #[error("resource_not_found")]
    Missing,
}
impl IntoResponse for ResourceError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Missing => (StatusCode::NOT_FOUND, "resource_not_found"),
        };
        (status, Json(serde_json::json!({"code":code}))).into_response()
    }
}
