use crate::{Error, Failure, planning, software_publication};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Error::Conflict => (StatusCode::CONFLICT, "operation_conflict"),
            Error::CommitUnknown => (StatusCode::SERVICE_UNAVAILABLE, "operation_unknown"),
            Error::RollbackFailed => (
                StatusCode::SERVICE_UNAVAILABLE,
                "operation_rollback_unconfirmed",
            ),
            Error::Malformed => (StatusCode::BAD_REQUEST, "malformed_request"),
            Error::CertificateRequest => (StatusCode::BAD_REQUEST, "invalid_certificate_request"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_identity"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
            Error::NotFound => (StatusCode::NOT_FOUND, "inventory_not_found"),
            Error::Unsupported => (StatusCode::NOT_IMPLEMENTED, "action_not_supported"),
            Error::Unavailable(Failure::AuditIntegrity) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "audit_integrity_error")
            }
            Error::Unavailable(
                Failure::AuditIsolation | Failure::AuditContract | Failure::AuditAdmission,
            ) => (StatusCode::INTERNAL_SERVER_ERROR, "audit_contract_error"),
            Error::Group(m) => (
                StatusCode::NOT_FOUND,
                match m {
                    rss_mdm_inventory_service::groups::GroupMissing::Group => "group_not_found",
                    rss_mdm_inventory_service::groups::GroupMissing::Rule => "group_rule_not_found",
                    rss_mdm_inventory_service::groups::GroupMissing::Device => {
                        "planning_device_not_found"
                    }
                },
            ),
            Error::Planning(planning::error::PlanningError::Missing(m)) => (
                StatusCode::NOT_FOUND,
                match m {
                    planning::error::Missing::Device => "planning_device_not_found",
                    planning::error::Missing::Group => "group_not_found",
                    planning::error::Missing::Scope => "scope_not_found",
                    planning::error::Missing::Policy => "policy_not_found",
                    planning::error::Missing::Rule => "group_rule_not_found",
                },
            ),
            Error::Resource(_) => (StatusCode::NOT_FOUND, "resource_not_found"),
            Error::Execution(e) => (
                StatusCode::NOT_FOUND,
                match e {
                    rss_mdm_execution_service::missing::ExecutionError::MissingOperation => {
                        "operation_not_found"
                    }
                    rss_mdm_execution_service::missing::ExecutionError::MissingTask => {
                        "task_not_found"
                    }
                },
            ),
            Error::Publication(e) => (
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
            Error::Configuration(_) | Error::Unavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
        };
        let body = serde_json::json!({"code":code});
        let mut response = (status, Json(body)).into_response();
        response.extensions_mut().insert(self);
        response
    }
}
