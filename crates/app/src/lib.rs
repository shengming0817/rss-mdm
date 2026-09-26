#![deny(clippy::cognitive_complexity)]
//! Embedded authentication assembly and product-owned device/resource authorization.
#[cfg(test)]
extern crate self as rss_mdm_app;
mod action_admission;
mod assets;
#[cfg(test)]
mod audit_integration_tests;
pub mod authorization;
mod automation;
mod collection;
mod database;
pub mod device;
mod enrollment;
pub mod execution;

mod flow;
mod http_operation;
mod inventory_runtime;
mod operations;
pub mod planning;
#[cfg(test)]
#[allow(
    dead_code,
    reason = "the shared publication fixture exposes scenarios used by separate test modules"
)]
#[path = "../tests/publication_support/mod.rs"]
mod publication_support;
mod registration_lifecycle;
pub mod resource_catalog;
mod task_content;
mod transaction;
use database::Database;

mod audit_budget;
mod diagnostic;
mod error_projection;
pub use diagnostic::{ConfigIssue, Failure, Monotonic, ProcessError, install_diagnostics};
mod agent;
mod api;
mod apple;
mod clock;
pub mod config;
mod identity;
mod identity_audit;
#[cfg(test)]
mod identity_fixture;
#[cfg(test)]
mod identity_t2;
mod lifecycle;
pub mod maintenance;
pub mod migration;
mod native;
pub mod software_publication;
pub mod windows;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
pub use lifecycle::{serve, signal};

#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid product configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error(transparent)]
    Planning(#[from] planning::error::PlanningError),
    #[error(transparent)]
    Resource(#[from] resource_catalog::error::ResourceError),
    #[error(transparent)]
    Execution(#[from] execution::error::ExecutionError),
    #[error(transparent)]
    Publication(#[from] software_publication::error::PublicationHttpError),
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("operation identity or enrollment/registration state conflict")]
    Conflict,
    #[error("commit outcome unknown; retry the same operation")]
    CommitUnknown,
    #[error("rollback not acknowledged; original attempt remains unresolved")]
    RollbackFailed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("inventory not found")]
    NotFound,
    #[error("action not supported")]
    Unsupported,
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let projected = match &self {
            Self::Planning(e) => Some(e.clone().into_response()),
            Self::Resource(e) => Some(e.clone().into_response()),
            Self::Execution(e) => Some(e.clone().into_response()),
            Self::Publication(e) => Some(e.clone().into_response()),
            _ => None,
        };
        if let Some(mut response) = projected {
            response.extensions_mut().insert(self);
            return response;
        }
        let (status, code) = match &self {
            Self::Conflict => (StatusCode::CONFLICT, "operation_conflict"),
            Self::CommitUnknown => (StatusCode::SERVICE_UNAVAILABLE, "operation_unknown"),
            Self::RollbackFailed => (
                StatusCode::SERVICE_UNAVAILABLE,
                "operation_rollback_unconfirmed",
            ),
            Self::Malformed => (StatusCode::BAD_REQUEST, "malformed_request"),
            Self::CertificateRequest => (StatusCode::BAD_REQUEST, "invalid_certificate_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_identity"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
            Self::NotFound => (StatusCode::NOT_FOUND, "inventory_not_found"),
            Self::Unsupported => (StatusCode::NOT_IMPLEMENTED, "action_not_supported"),
            Self::Unavailable(Failure::AuditIntegrity) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "audit_integrity_error")
            }
            Self::Unavailable(
                Failure::AuditIsolation | Failure::AuditContract | Failure::AuditAdmission,
            ) => (StatusCode::INTERNAL_SERVER_ERROR, "audit_contract_error"),
            Self::Planning(_) | Self::Resource(_) | Self::Execution(_) | Self::Publication(_) => {
                unreachable!("domain errors projected above")
            }
            Self::Configuration(_) | Self::Unavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
        };
        let body = serde_json::json!({"code":code});
        let mut response = (status, Json(body)).into_response();
        response.extensions_mut().insert(self);
        response
    }
}

#[cfg(test)]
mod audit_test_support;

impl Error {
    pub(crate) fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::NotFound
                | Self::Planning(planning::error::PlanningError::Missing(_))
                | Self::Resource(resource_catalog::error::ResourceError::Missing)
                | Self::Execution(_)
                | Self::Publication(_)
        )
    }
}
