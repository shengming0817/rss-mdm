//! Product-owned OIDC relying party, local session and resource authorization.
mod access;
mod access_store;
mod audit;
mod enrollment;
pub use access_store::AccessStore;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure, Monotonic, ProcessError};
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

#[derive(Clone, Copy, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid product configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error("operation identity or grant state conflict")]
    Conflict,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("identity server rejected request")]
    IdentityServer {
        code: rss_identity_contracts::ValidationFailureCode,
        correlation_id: uuid::Uuid,
    },
    #[error("inventory not found")]
    NotFound,
    #[error("action not supported")]
    Unsupported,
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Conflict => (StatusCode::CONFLICT, "operation_conflict"),
            Self::CommitUnknown => (StatusCode::SERVICE_UNAVAILABLE, "operation_unknown"),
            Self::Malformed => (StatusCode::BAD_REQUEST, "malformed_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_identity"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
            Self::NotFound => (StatusCode::NOT_FOUND, "inventory_not_found"),
            Self::Unsupported => (StatusCode::NOT_IMPLEMENTED, "action_not_supported"),
            Self::IdentityServer {
                code:
                    rss_identity_contracts::ValidationFailureCode::InvalidCredential
                    | rss_identity_contracts::ValidationFailureCode::IdentityNotActive,
                ..
            } => (StatusCode::UNAUTHORIZED, "invalid_identity"),
            Self::Configuration(_) | Self::Unavailable(_) | Self::IdentityServer { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
        };
        let mut response = (status, Json(serde_json::json!({"code":code}))).into_response();
        response.extensions_mut().insert(self);
        response
    }
}
