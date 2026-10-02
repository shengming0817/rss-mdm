use crate::{ConfigIssue, Failure};
use rss_mdm_flow_service::{execution, planning};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid product configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error(transparent)]
    Service(rss_mdm_flow_service::Error),
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
impl From<rss_mdm_flow_service::Error> for Error {
    fn from(e: rss_mdm_flow_service::Error) -> Self {
        Self::Service(e)
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
impl From<rss_mdm_registration_service::enrollment::EnrollmentError> for Error {
    fn from(e: rss_mdm_registration_service::enrollment::EnrollmentError) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
impl From<rss_mdm_inventory_service::collection::CollectionError> for Error {
    fn from(e: rss_mdm_inventory_service::collection::CollectionError) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}
impl From<Error> for rss_mdm_flow_service::execution::channels::Rejection {
    fn from(e: Error) -> Self {
        use rss_mdm_flow_service::execution::channels::Rejection as R;
        match e {
            Error::CommitUnknown => R::CommitUnknown,
            Error::RollbackFailed => R::RollbackFailed,
            Error::Malformed | Error::CertificateRequest => R::Malformed,
            Error::Unauthorized => R::Unauthorized,
            Error::Forbidden => R::Forbidden,
            Error::Conflict => R::Conflict,
            Error::Unavailable(Failure::AuditIsolation) => R::AuditIsolation,
            Error::Unavailable(Failure::AuditAdmission) => R::AuditAdmission,
            Error::Unavailable(Failure::AuditIntegrity) => R::AuditIntegrity,
            Error::Unavailable(Failure::AuditContract) => R::AuditContract,
            Error::Unavailable(Failure::Audit) => R::Audit,
            Error::Unavailable(Failure::RequestDeadline) => R::Deadline,
            Error::Unavailable(Failure::Protocol) => R::Protocol,
            Error::Service(e) => e.into(),
            _ => R::Storage,
        }
    }
}
impl From<rss_mdm_certificate::Error> for Error {
    fn from(error: rss_mdm_certificate::Error) -> Self {
        use rss_mdm_certificate::Error as Certificate;
        match error {
            Certificate::Malformed => Self::Malformed,
            Certificate::CertificateRequest => Self::CertificateRequest,
            Certificate::Unauthorized => Self::Unauthorized,
            Certificate::Conflict => Self::Conflict,
            Certificate::Expired | Certificate::Signing => Self::Unavailable(Failure::Certificate),
        }
    }
}

impl From<rss_mdm_apple_mdm::Error> for Error {
    fn from(e: rss_mdm_apple_mdm::Error) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}

impl From<rss_mdm_registration_service::device::DeviceError> for Error {
    fn from(e: rss_mdm_registration_service::device::DeviceError) -> Self {
        rss_mdm_flow_service::Error::from(e).into()
    }
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        use axum::{Json, http::StatusCode};
        let (status, code) = match &self {
            Self::Conflict | Self::Service(rss_mdm_flow_service::Error::Conflict) => {
                (StatusCode::CONFLICT, "operation_conflict")
            }
            Self::CommitUnknown | Self::Service(rss_mdm_flow_service::Error::CommitUnknown) => {
                (StatusCode::SERVICE_UNAVAILABLE, "operation_unknown")
            }
            Self::RollbackFailed | Self::Service(rss_mdm_flow_service::Error::RollbackFailed) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "operation_rollback_unconfirmed",
            ),
            Self::Malformed | Self::Service(rss_mdm_flow_service::Error::Malformed) => {
                (StatusCode::BAD_REQUEST, "malformed_request")
            }
            Self::CertificateRequest
            | Self::Service(rss_mdm_flow_service::Error::CertificateRequest) => {
                (StatusCode::BAD_REQUEST, "invalid_certificate_request")
            }
            Self::Unauthorized | Self::Service(rss_mdm_flow_service::Error::Unauthorized) => {
                (StatusCode::UNAUTHORIZED, "invalid_identity")
            }
            Self::Forbidden | Self::Service(rss_mdm_flow_service::Error::Forbidden) => {
                (StatusCode::FORBIDDEN, "permission_denied")
            }
            Self::NotFound | Self::Service(rss_mdm_flow_service::Error::NotFound) => {
                (StatusCode::NOT_FOUND, "inventory_not_found")
            }
            Self::Unsupported | Self::Service(rss_mdm_flow_service::Error::Unsupported) => {
                (StatusCode::NOT_IMPLEMENTED, "action_not_supported")
            }
            Self::Unavailable(Failure::AuditIntegrity)
            | Self::Service(rss_mdm_flow_service::Error::Unavailable(
                rss_mdm_flow_service::Failure::AuditIntegrity,
            )) => (StatusCode::INTERNAL_SERVER_ERROR, "audit_integrity_error"),
            Self::Unavailable(
                Failure::AuditIsolation | Failure::AuditContract | Failure::AuditAdmission,
            )
            | Self::Service(rss_mdm_flow_service::Error::Unavailable(
                rss_mdm_flow_service::Failure::AuditIsolation
                | rss_mdm_flow_service::Failure::AuditContract
                | rss_mdm_flow_service::Failure::AuditAdmission,
            )) => (StatusCode::INTERNAL_SERVER_ERROR, "audit_contract_error"),
            Self::Service(rss_mdm_flow_service::Error::Planning(
                planning::error::PlanningError::Missing(m),
            )) => (
                StatusCode::NOT_FOUND,
                match m {
                    planning::error::Missing::Device => "planning_device_not_found",
                    planning::error::Missing::Group => "group_not_found",
                    planning::error::Missing::Scope => "scope_not_found",
                    planning::error::Missing::Policy => "policy_not_found",
                    planning::error::Missing::Rule => "group_rule_not_found",
                },
            ),
            Self::Service(rss_mdm_flow_service::Error::Resource(_)) => {
                (StatusCode::NOT_FOUND, "resource_not_found")
            }
            Self::Service(rss_mdm_flow_service::Error::Execution(e)) => (
                StatusCode::NOT_FOUND,
                match e {
                    execution::error::ExecutionError::MissingOperation => "operation_not_found",
                    execution::error::ExecutionError::MissingTask => "task_not_found",
                },
            ),
            Self::Service(rss_mdm_flow_service::Error::Publication(e)) => {
                (StatusCode::NOT_FOUND, e.code())
            }
            Self::Service(_) | Self::Configuration(_) | Self::Unavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
        };
        let body = serde_json::json!({"code":code});
        let mut response = (status, Json(body)).into_response();
        response.extensions_mut().insert(self);
        response
    }
}
