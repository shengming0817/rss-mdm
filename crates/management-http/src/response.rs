use crate::{Error, Failure, planning, software_publication};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Error::FirstUseNotReady => (StatusCode::CONFLICT, "first_use_not_ready"),
            Error::FirstUseOperationMissing => {
                (StatusCode::NOT_FOUND, "first_use_operation_not_found")
            }
            Error::Archive(e) => archive_error(e),
            Error::RecoveryCredentials(e) => recovery_error(e),
            Error::MdmSoftwareDisabled => (StatusCode::CONFLICT, "mdm_software_disabled"),
            Error::EnrollmentPaused => (StatusCode::CONFLICT, "enrollment_paused"),
            Error::RegistrationLimit => (StatusCode::TOO_MANY_REQUESTS, "registration_limit"),
            Error::ResourceCursorInvalidated => {
                (StatusCode::CONFLICT, "resource_cursor_invalidated")
            }
            Error::Conflict => (StatusCode::CONFLICT, "operation_conflict"),
            Error::DeviceViewCursorInvalidated => {
                (StatusCode::CONFLICT, "device_view_cursor_invalidated")
            }
            Error::WindowsDeclaredEnrollmentNotReady => (
                StatusCode::CONFLICT,
                "windows_declared_enrollment_not_ready",
            ),
            Error::CommitUnknown => (StatusCode::SERVICE_UNAVAILABLE, "operation_unknown"),
            Error::RollbackFailed => (
                StatusCode::SERVICE_UNAVAILABLE,
                "operation_rollback_unconfirmed",
            ),
            Error::RequestTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
            Error::Malformed => (StatusCode::BAD_REQUEST, "malformed_request"),
            Error::CertificateRequest => (StatusCode::BAD_REQUEST, "invalid_certificate_request"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_identity"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
            Error::AgentPackage(reason) => (
                StatusCode::CONFLICT,
                match reason {
                    rss_mdm_software_service::agent_packages::Rejection::InstallerMismatch => {
                        "agent_package_installer_mismatch"
                    }
                    rss_mdm_software_service::agent_packages::Rejection::LifecycleNotAdmitted => {
                        "agent_package_lifecycle_not_admitted"
                    }
                    rss_mdm_software_service::agent_packages::Rejection::SourceNotAdmitted => {
                        "agent_package_source_not_admitted"
                    }
                    rss_mdm_software_service::agent_packages::Rejection::BindingNotAdmitted => {
                        "agent_package_binding_not_admitted"
                    }
                },
            ),
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
                    software_publication::error::PublicationError::MissingPublication => {
                        "software_publication_not_found"
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

fn archive_error(error: &rss_mdm_certificate_archive_service::Error) -> (StatusCode, &'static str) {
    use rss_mdm_certificate_archive_service::Error as E;
    match error {
        E::Malformed => (StatusCode::BAD_REQUEST, "malformed_request"),
        E::Material => (StatusCode::BAD_REQUEST, "archive_material_invalid"),
        E::KeyMismatch => (StatusCode::BAD_REQUEST, "archive_key_mismatch"),
        E::Password => (StatusCode::FORBIDDEN, "archive_password_rejected"),
        E::Locked => (StatusCode::LOCKED, "archive_locked"),
        E::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_identity"),
        E::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
        E::NotFound => (StatusCode::NOT_FOUND, "archive_not_found"),
        E::Conflict => (StatusCode::CONFLICT, "operation_conflict"),
        E::Integrity => (StatusCode::INTERNAL_SERVER_ERROR, "archive_integrity_error"),
        E::Storage | E::Audit => (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
        E::Limited => (StatusCode::TOO_MANY_REQUESTS, "request_limited"),
        E::CommitUnknown => (StatusCode::SERVICE_UNAVAILABLE, "operation_unknown"),
        E::RollbackFailed => (
            StatusCode::SERVICE_UNAVAILABLE,
            "operation_rollback_unconfirmed",
        ),
    }
}

fn recovery_error(e: &rss_mdm_recovery_credentials::Error) -> (StatusCode, &'static str) {
    use rss_mdm_recovery_credentials::Error as E;
    match e {
        E::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_identity"),
        E::Forbidden => (StatusCode::FORBIDDEN, "permission_denied"),
        E::Malformed => (StatusCode::BAD_REQUEST, "malformed_request"),
        E::NotFound => (StatusCode::NOT_FOUND, "recovery_credential_not_found"),
        E::Conflict => (StatusCode::CONFLICT, "operation_conflict"),
        E::Integrity => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "recovery_credential_integrity",
        ),
        E::CommitUnknown => (StatusCode::SERVICE_UNAVAILABLE, "operation_unknown"),
        E::RollbackFailed => (
            StatusCode::SERVICE_UNAVAILABLE,
            "operation_rollback_unconfirmed",
        ),
        E::Unsupported => (StatusCode::NOT_IMPLEMENTED, "action_not_supported"),
        E::Configuration | E::Storage | E::Audit => {
            (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
        }
    }
}
