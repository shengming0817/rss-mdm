use crate::{Error, Failure, execution, planning, software_publication};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
impl IntoResponse for Error {
    fn into_response(self) -> Response {
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
            Self::Planning(planning::error::PlanningError::Missing(m)) => (
                StatusCode::NOT_FOUND,
                match m {
                    planning::error::Missing::Device => "planning_device_not_found",
                    planning::error::Missing::Group => "group_not_found",
                    planning::error::Missing::Scope => "scope_not_found",
                    planning::error::Missing::Policy => "policy_not_found",
                    planning::error::Missing::Rule => "group_rule_not_found",
                },
            ),
            Self::Resource(_) => (StatusCode::NOT_FOUND, "resource_not_found"),
            Self::Execution(e) => (
                StatusCode::NOT_FOUND,
                match e {
                    execution::error::ExecutionError::MissingOperation => "operation_not_found",
                    execution::error::ExecutionError::MissingTask => "task_not_found",
                },
            ),
            Self::Publication(e) => (
                StatusCode::NOT_FOUND,
                match e {
                    software_publication::error::PublicationError::MissingSource => {
                        "software_source_not_found"
                    }
                    software_publication::error::PublicationError::MissingCandidate => {
                        "software_candidate_not_found"
                    }
                },
            ),
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
