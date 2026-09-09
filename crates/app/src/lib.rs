//! Product-owned OIDC relying party, local session and resource authorization.
mod access;
mod diagnostic;
pub use diagnostic::ProcessError;
mod api;
pub mod config;
mod identity;
mod lifecycle;
pub mod migration;
mod sessions;
pub use api::application;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
pub use lifecycle::{serve, signal};

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid product configuration")]
    Configuration,
    #[error("invalid request")]
    Malformed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("dependency unavailable")]
    Unavailable,
    #[error("inventory not found")]
    NotFound,
    #[error("action not supported")]
    Unsupported,
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Malformed => (StatusCode::BAD_REQUEST, "malformed_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_identity"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
            Self::NotFound => (StatusCode::NOT_FOUND, "inventory_not_found"),
            Self::Unsupported => (StatusCode::NOT_IMPLEMENTED, "action_not_supported"),
            Self::Configuration | Self::Unavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
        };
        (status, Json(serde_json::json!({"code":code}))).into_response()
    }
}
