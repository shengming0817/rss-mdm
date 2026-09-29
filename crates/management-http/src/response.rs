use crate::{Error, Failure, execution, planning, software_publication};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match &self.0 {
            rss_mdm_flow_service::Error::Conflict => (StatusCode::CONFLICT, "operation_conflict"),
            rss_mdm_flow_service::Error::CommitUnknown => {
                (StatusCode::SERVICE_UNAVAILABLE, "operation_unknown")
            }
            rss_mdm_flow_service::Error::RollbackFailed => (
                StatusCode::SERVICE_UNAVAILABLE,
                "operation_rollback_unconfirmed",
            ),
            rss_mdm_flow_service::Error::Malformed => {
                (StatusCode::BAD_REQUEST, "malformed_request")
            }
            rss_mdm_flow_service::Error::CertificateRequest => {
                (StatusCode::BAD_REQUEST, "invalid_certificate_request")
            }
            rss_mdm_flow_service::Error::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "invalid_identity")
            }
            rss_mdm_flow_service::Error::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
            rss_mdm_flow_service::Error::NotFound => (StatusCode::NOT_FOUND, "inventory_not_found"),
            rss_mdm_flow_service::Error::Unsupported => {
                (StatusCode::NOT_IMPLEMENTED, "action_not_supported")
            }
            rss_mdm_flow_service::Error::Unavailable(Failure::AuditIntegrity) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "audit_integrity_error")
            }
            rss_mdm_flow_service::Error::Unavailable(
                Failure::AuditIsolation | Failure::AuditContract | Failure::AuditAdmission,
            ) => (StatusCode::INTERNAL_SERVER_ERROR, "audit_contract_error"),
            rss_mdm_flow_service::Error::Planning(planning::error::PlanningError::Missing(m)) => (
                StatusCode::NOT_FOUND,
                match m {
                    planning::error::Missing::Device => "planning_device_not_found",
                    planning::error::Missing::Group => "group_not_found",
                    planning::error::Missing::Scope => "scope_not_found",
                    planning::error::Missing::Policy => "policy_not_found",
                    planning::error::Missing::Rule => "group_rule_not_found",
                },
            ),
            rss_mdm_flow_service::Error::Resource(_) => {
                (StatusCode::NOT_FOUND, "resource_not_found")
            }
            rss_mdm_flow_service::Error::Execution(e) => (
                StatusCode::NOT_FOUND,
                match e {
                    execution::error::ExecutionError::MissingOperation => "operation_not_found",
                    execution::error::ExecutionError::MissingTask => "task_not_found",
                },
            ),
            rss_mdm_flow_service::Error::Publication(e) => (
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
            rss_mdm_flow_service::Error::Configuration(_)
            | rss_mdm_flow_service::Error::Unavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
        };
        let body = serde_json::json!({"code":code});
        let mut response = (status, Json(body)).into_response();
        response.extensions_mut().insert(self);
        response
    }
}
