#![deny(clippy::cognitive_complexity)]
//! Embedded authentication assembly and product-owned device/resource authorization.
#[cfg(test)]
extern crate self as rss_mdm_app;
mod access;
mod access_store;
mod audit;
pub mod authorization;
mod collection;
mod commands;
pub mod device;
mod enrollment;
mod inventory_runtime;
mod management;
pub use access_store::AccessStore;
pub use management::Missing as ManagementObject;
mod diagnostic;
pub use diagnostic::{ConfigIssue, Failure, Monotonic, ProcessError, install_diagnostics};
mod api;
mod clock;
pub mod config;
mod enrollment_credentials;
mod identity;
#[cfg(test)]
mod identity_fixture;
#[cfg(test)]
mod identity_t2;
mod lifecycle;
pub mod maintenance;
pub mod migration;
pub mod software_publication;
pub mod windows;
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
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("operation identity or enrollment/registration state conflict")]
    Conflict,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("management object not found")]
    ManagementNotFound(ManagementObject),
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
            Self::CertificateRequest => (StatusCode::BAD_REQUEST, "invalid_certificate_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_identity"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
            Self::ManagementNotFound(object) => (StatusCode::NOT_FOUND, object.code()),
            Self::NotFound => (StatusCode::NOT_FOUND, "inventory_not_found"),
            Self::Unsupported => (StatusCode::NOT_IMPLEMENTED, "action_not_supported"),
            Self::Configuration(_) | Self::Unavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
        };
        let mut response = (status, Json(serde_json::json!({"code":code}))).into_response();
        response.extensions_mut().insert(self);
        response
    }
}
