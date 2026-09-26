use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum PublicationHttpError {
    #[error("software_source_not_found")]
    MissingSource,
    #[error("software_candidate_not_found")]
    MissingCandidate,
}
impl IntoResponse for PublicationHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::MissingSource => (StatusCode::NOT_FOUND, "software_source_not_found"),
            Self::MissingCandidate => (StatusCode::NOT_FOUND, "software_candidate_not_found"),
        };
        (status, Json(serde_json::json!({"code":code}))).into_response()
    }
}
