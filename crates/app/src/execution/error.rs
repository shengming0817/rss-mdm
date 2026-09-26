use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum ExecutionError {
    #[error("operation_not_found")]
    MissingOperation,
    #[error("task_not_found")]
    MissingTask,
}
impl IntoResponse for ExecutionError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::MissingOperation => (StatusCode::NOT_FOUND, "operation_not_found"),
            Self::MissingTask => (StatusCode::NOT_FOUND, "task_not_found"),
        };
        (status, Json(serde_json::json!({"code":code}))).into_response()
    }
}
