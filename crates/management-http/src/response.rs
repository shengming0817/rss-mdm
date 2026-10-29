use crate::{Error, Failure, software_publication};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let code = match &self {
            Error::FirstUseNotReady => Code::FirstUseNotReady,
            Error::FirstUseOperationMissing => Code::FirstUseOperationNotFound,
            Error::Archive(e) => archive_error(e),
            Error::RecoveryCredentials(e) => recovery_error(e),
            Error::MdmSoftwareDisabled => Code::MdmSoftwareDisabled,
            Error::EnrollmentPaused => Code::EnrollmentPaused,
            Error::RegistrationLimit => Code::RegistrationLimit,
            Error::ResourceCursorInvalidated => Code::ResourceCursorInvalidated,
            Error::Conflict => Code::OperationConflict,
            Error::DeviceViewCursorInvalidated => Code::DeviceViewCursorInvalidated,
            Error::WindowsDeclaredEnrollmentNotReady => Code::WindowsDeclaredEnrollmentNotReady,
            Error::CommitUnknown => Code::OperationUnknown,
            Error::RollbackFailed => Code::OperationRollbackUnconfirmed,
            Error::RequestTooLarge => Code::RequestTooLarge,
            Error::Malformed => Code::MalformedRequest,
            Error::CertificateRequest => Code::InvalidCertificateRequest,
            Error::Unauthorized => Code::InvalidIdentity,
            Error::Forbidden => Code::PermissionDenied,
            Error::AgentPackage(reason) => match reason {
                rss_mdm_software_service::agent_packages::Rejection::InstallerMismatch => {
                    Code::AgentPackageInstallerMismatch
                }
                rss_mdm_software_service::agent_packages::Rejection::LifecycleNotAdmitted => {
                    Code::AgentPackageLifecycleNotAdmitted
                }
                rss_mdm_software_service::agent_packages::Rejection::SourceNotAdmitted => {
                    Code::AgentPackageSourceNotAdmitted
                }
                rss_mdm_software_service::agent_packages::Rejection::BindingNotAdmitted => {
                    Code::AgentPackageBindingNotAdmitted
                }
            },
            Error::NotFound => Code::InventoryNotFound,
            Error::Unsupported => Code::ActionNotSupported,
            Error::Unavailable(Failure::AuditIntegrity) => Code::AuditIntegrityError,
            Error::Unavailable(
                Failure::AuditIsolation | Failure::AuditContract | Failure::AuditAdmission,
            ) => Code::AuditContractError,
            Error::Group(m) => match m {
                rss_mdm_inventory_service::groups::GroupMissing::Group => Code::GroupNotFound,
                rss_mdm_inventory_service::groups::GroupMissing::Rule => Code::GroupRuleNotFound,
                rss_mdm_inventory_service::groups::GroupMissing::Device => {
                    Code::PlanningDeviceNotFound
                }
            },
            Error::ScopeNotFound => Code::ScopeNotFound,
            Error::PolicyMissing => Code::PolicyNotFound,
            Error::Resource(_) => Code::ResourceNotFound,
            Error::Execution(e) => match e {
                rss_mdm_execution_service::missing::ExecutionError::MissingOperation => {
                    Code::OperationNotFound
                }
                rss_mdm_execution_service::missing::ExecutionError::MissingTask => {
                    Code::TaskNotFound
                }
            },
            Error::Publication(e) => match e {
                software_publication::error::PublicationError::MissingSource => {
                    Code::SoftwareSourceNotFound
                }
                software_publication::error::PublicationError::MissingPublication => {
                    Code::SoftwarePublicationNotFound
                }
            },
            Error::Configuration(_) | Error::Unavailable(_) => Code::ServiceUnavailable,
        };
        let mut response = (code.status(), Json(Body { code })).into_response();
        response.extensions_mut().insert(self);
        response
    }
}

fn archive_error(error: &rss_mdm_certificate_archive_service::Error) -> Code {
    use rss_mdm_certificate_archive_service::Error as E;
    match error {
        E::Malformed => Code::MalformedRequest,
        E::Material => Code::ArchiveMaterialInvalid,
        E::KeyMismatch => Code::ArchiveKeyMismatch,
        E::Password => Code::ArchivePasswordRejected,
        E::Locked => Code::ArchiveLocked,
        E::Unauthorized => Code::InvalidIdentity,
        E::Forbidden => Code::PermissionDenied,
        E::NotFound => Code::ArchiveNotFound,
        E::Conflict => Code::OperationConflict,
        E::Integrity => Code::ArchiveIntegrityError,
        E::Storage | E::Audit => Code::ServiceUnavailable,
        E::Limited => Code::RequestLimited,
        E::CommitUnknown => Code::OperationUnknown,
        E::RollbackFailed => Code::OperationRollbackUnconfirmed,
    }
}

fn recovery_error(e: &rss_mdm_recovery_credentials::Error) -> Code {
    use rss_mdm_recovery_credentials::Error as E;
    match e {
        E::Unauthorized => Code::InvalidIdentity,
        E::Forbidden => Code::PermissionDenied,
        E::Malformed => Code::MalformedRequest,
        E::NotFound => Code::RecoveryCredentialNotFound,
        E::Conflict => Code::OperationConflict,
        E::Integrity => Code::RecoveryCredentialIntegrity,
        E::CommitUnknown => Code::OperationUnknown,
        E::RollbackFailed => Code::OperationRollbackUnconfirmed,
        E::Unsupported => Code::ActionNotSupported,
        E::Configuration | E::Storage | E::Audit => Code::ServiceUnavailable,
    }
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Code {
    ActionNotSupported,
    AgentPackageBindingNotAdmitted,
    AgentPackageInstallerMismatch,
    AgentPackageLifecycleNotAdmitted,
    AgentPackageSourceNotAdmitted,
    ArchiveIntegrityError,
    ArchiveKeyMismatch,
    ArchiveLocked,
    ArchiveMaterialInvalid,
    ArchiveNotFound,
    ArchivePasswordRejected,
    AuditContractError,
    AuditIntegrityError,
    DeviceViewCursorInvalidated,
    EnrollmentPaused,
    FirstUseNotReady,
    FirstUseOperationNotFound,
    GroupNotFound,
    GroupRuleNotFound,
    InvalidCertificateRequest,
    InvalidIdentity,
    InventoryNotFound,
    MalformedRequest,
    MdmSoftwareDisabled,
    OperationConflict,
    OperationNotFound,
    OperationRollbackUnconfirmed,
    OperationUnknown,
    PermissionDenied,
    PlanningDeviceNotFound,
    PolicyNotFound,
    RecoveryCredentialIntegrity,
    RecoveryCredentialNotFound,
    RegistrationLimit,
    RequestLimited,
    RequestTooLarge,
    ResourceCursorInvalidated,
    ResourceNotFound,
    ScopeNotFound,
    ServiceUnavailable,
    SoftwarePublicationNotFound,
    SoftwareSourceNotFound,
    TaskNotFound,
    WindowsDeclaredEnrollmentNotReady,
}
impl Code {
    fn status(self) -> StatusCode {
        match self {
            Self::ActionNotSupported => StatusCode::NOT_IMPLEMENTED,
            Self::AgentPackageBindingNotAdmitted => StatusCode::CONFLICT,
            Self::AgentPackageInstallerMismatch => StatusCode::CONFLICT,
            Self::AgentPackageLifecycleNotAdmitted => StatusCode::CONFLICT,
            Self::AgentPackageSourceNotAdmitted => StatusCode::CONFLICT,
            Self::ArchiveIntegrityError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ArchiveKeyMismatch => StatusCode::BAD_REQUEST,
            Self::ArchiveLocked => StatusCode::LOCKED,
            Self::ArchiveMaterialInvalid => StatusCode::BAD_REQUEST,
            Self::ArchiveNotFound => StatusCode::NOT_FOUND,
            Self::ArchivePasswordRejected => StatusCode::FORBIDDEN,
            Self::AuditContractError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::AuditIntegrityError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DeviceViewCursorInvalidated => StatusCode::CONFLICT,
            Self::EnrollmentPaused => StatusCode::CONFLICT,
            Self::FirstUseNotReady => StatusCode::CONFLICT,
            Self::FirstUseOperationNotFound => StatusCode::NOT_FOUND,
            Self::GroupNotFound => StatusCode::NOT_FOUND,
            Self::GroupRuleNotFound => StatusCode::NOT_FOUND,
            Self::InvalidCertificateRequest => StatusCode::BAD_REQUEST,
            Self::InvalidIdentity => StatusCode::UNAUTHORIZED,
            Self::InventoryNotFound => StatusCode::NOT_FOUND,
            Self::MalformedRequest => StatusCode::BAD_REQUEST,
            Self::MdmSoftwareDisabled => StatusCode::CONFLICT,
            Self::OperationConflict => StatusCode::CONFLICT,
            Self::OperationNotFound => StatusCode::NOT_FOUND,
            Self::OperationRollbackUnconfirmed => StatusCode::SERVICE_UNAVAILABLE,
            Self::OperationUnknown => StatusCode::SERVICE_UNAVAILABLE,
            Self::PermissionDenied => StatusCode::FORBIDDEN,
            Self::PlanningDeviceNotFound => StatusCode::NOT_FOUND,
            Self::PolicyNotFound => StatusCode::NOT_FOUND,
            Self::RecoveryCredentialIntegrity => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RecoveryCredentialNotFound => StatusCode::NOT_FOUND,
            Self::RegistrationLimit => StatusCode::TOO_MANY_REQUESTS,
            Self::RequestLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ResourceCursorInvalidated => StatusCode::CONFLICT,
            Self::ResourceNotFound => StatusCode::NOT_FOUND,
            Self::ScopeNotFound => StatusCode::NOT_FOUND,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::SoftwarePublicationNotFound => StatusCode::NOT_FOUND,
            Self::SoftwareSourceNotFound => StatusCode::NOT_FOUND,
            Self::TaskNotFound => StatusCode::NOT_FOUND,
            Self::WindowsDeclaredEnrollmentNotReady => StatusCode::CONFLICT,
        }
    }
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Body {
    code: Code,
}
impl rss_mdm_http_contract::signature::Output for Error {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        let codes = rss_mdm_http_contract::signature::Schema::response::<Code>();
        codes
            .string_values()
            .iter()
            .map(|value| {
                let code: Code =
                    serde_json::from_value(value.clone()).expect("actual management error code");
                let mut response = rss_mdm_http_contract::signature::Response::json::<Body>(
                    code.status().as_u16(),
                );
                response
                    .body
                    .as_mut()
                    .expect("JSON error body")
                    .schema
                    .value["properties"]["code"]["const"] =
                    serde_json::to_value(code).expect("closed error code");
                response
            })
            .collect()
    }
}
