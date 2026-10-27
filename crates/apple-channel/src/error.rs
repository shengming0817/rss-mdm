use crate::{ConfigIssue, Failure};
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum Error {
    #[error("invalid protocol configuration")]
    Configuration(ConfigIssue),
    #[error("invalid request")]
    Malformed,
    #[error("certificate request rejected")]
    CertificateRequest,
    #[error("operation conflict")]
    Conflict,
    #[error("new registration admission paused")]
    EnrollmentPaused,
    #[error("commit outcome unknown")]
    CommitUnknown,
    #[error("rollback unconfirmed")]
    RollbackFailed,
    #[error("identity rejected")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("dependency unavailable")]
    Unavailable(Failure),
    #[error("inventory not found")]
    NotFound,
    #[error("object not found")]
    Missing(Missing),
    #[error("action unsupported")]
    Unsupported,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Missing {
    Resource,
    Operation,
    Task,
    SoftwareSource,
    SoftwarePublication,
}
impl Missing {
    fn code(self) -> Code {
        match self {
            Self::Resource => Code::ResourceNotFound,
            Self::Operation => Code::OperationNotFound,
            Self::Task => Code::TaskNotFound,
            Self::SoftwareSource => Code::SoftwareSourceNotFound,
            Self::SoftwarePublication => Code::SoftwarePublicationNotFound,
        }
    }
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        rss_mdm_authorization_service::Error::from(e).into()
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as A;
        match e {
            A::Malformed => Self::Malformed,
            A::Unauthorized => Self::Unauthorized,
            A::Forbidden => Self::Forbidden,
            A::Conflict => Self::Conflict,
            A::CommitUnknown => Self::CommitUnknown,
            A::RollbackFailed => Self::RollbackFailed,
            A::Deadline => Self::Unavailable(Failure::RequestDeadline),
            A::Audit(e) => e.as_ref().into(),
            A::Corrupt | A::Storage | A::Configuration => Self::Unavailable(Failure::Database),
        }
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        use rss_mdm_registration_service::Error as R;
        match e {
            R::Agent(_) => Self::Unauthorized,
            R::Malformed => Self::Malformed,
            R::Unauthorized => Self::Unauthorized,
            R::Forbidden => Self::Forbidden,
            R::Conflict => Self::Conflict,
            R::CommitUnknown => Self::CommitUnknown,
            R::RollbackFailed => Self::RollbackFailed,
            R::Deadline => Self::Unavailable(Failure::RequestDeadline),
            R::NotFound => Self::NotFound,
            R::Audit(e) => e.as_ref().into(),
            R::Corrupt | R::Storage | R::Retirement | R::Configuration => {
                Self::Unavailable(Failure::Database)
            }
            R::EnrollmentPaused => Self::EnrollmentPaused,
            R::Capacity | R::RegistrationLimit => Self::Unavailable(Failure::Capacity),
            R::Runtime => Self::Unavailable(Failure::Runtime),
        }
    }
}
impl From<rss_mdm_registration_service::enrollment::EnrollmentError> for Error {
    fn from(_: rss_mdm_registration_service::enrollment::EnrollmentError) -> Self {
        Self::Malformed
    }
}
impl From<rss_mdm_registration_service::device::DeviceError> for Error {
    fn from(_: rss_mdm_registration_service::device::DeviceError) -> Self {
        Self::Malformed
    }
}
impl From<rss_mdm_inventory_service::collection::CollectionError> for Error {
    fn from(_: rss_mdm_inventory_service::collection::CollectionError) -> Self {
        Self::Conflict
    }
}
impl From<rss_mdm_inventory_service::Error> for Error {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        use rss_mdm_inventory_service::Error as I;
        match e {
            I::Malformed => Self::Malformed,
            I::Unauthorized => Self::Unauthorized,
            I::Forbidden => Self::Forbidden,
            I::Conflict => Self::Conflict,
            I::CommitUnknown => Self::CommitUnknown,
            I::RollbackFailed => Self::RollbackFailed,
            I::NotFound | I::Group(_) => Self::NotFound,
            I::Audit(e) => e.as_ref().into(),
            I::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_inventory_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_inventory_service::Failure::Audit => Failure::Audit,
                rss_mdm_inventory_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_inventory_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_inventory_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_inventory_service::Failure::AuditContract => Failure::AuditContract,

                other => Failure::Inventory(other),
            }),
        }
    }
}
impl From<rss_mdm_audit_integration::InvalidFact> for Error {
    fn from(e: rss_mdm_audit_integration::InvalidFact) -> Self {
        rss_mdm_audit_integration::Error::Fact(e).into()
    }
}
impl From<rss_mdm_audit_integration::Error> for Error {
    fn from(e: rss_mdm_audit_integration::Error) -> Self {
        Self::from(&e)
    }
}
impl From<&rss_mdm_audit_integration::Error> for Error {
    fn from(e: &rss_mdm_audit_integration::Error) -> Self {
        use rss_mdm_audit_integration::ErrorClass as A;
        match e.class() {
            A::CommitUnknown => Self::CommitUnknown,
            A::RollbackFailed => Self::RollbackFailed,
            A::RequestDeadline => Self::Unavailable(Failure::RequestDeadline),
            A::Audit => Self::Unavailable(Failure::Audit),
            A::AuditIntegrity => Self::Unavailable(Failure::AuditIntegrity),
            A::AuditAdmission => Self::Unavailable(Failure::AuditAdmission),
            A::AuditIsolation => Self::Unavailable(Failure::AuditIsolation),
            A::AuditContract => Self::Unavailable(Failure::AuditContract),
        }
    }
}
impl From<rss_mdm_execution_service::Error> for Error {
    fn from(e: rss_mdm_execution_service::Error) -> Self {
        use rss_mdm_execution_service::Error as E;
        match e { E::MdmSoftwareDisabled => Self::Forbidden, E::Malformed => Self::Malformed, E::CertificateRequest => Self::CertificateRequest,
            E::Unauthorized => Self::Unauthorized, E::Forbidden => Self::Forbidden, E::Conflict | E::WindowsDeclaredEnrollmentNotReady => Self::Conflict,
            E::EnrollmentPaused => Self::EnrollmentPaused,
            E::CommitUnknown => Self::CommitUnknown, E::RollbackFailed => Self::RollbackFailed, E::Unsupported => Self::Unsupported,
            E::NotFound => Self::NotFound, E::Resource(_) => Self::Missing(Missing::Resource),
            E::Execution(e) => Self::Missing(match e { rss_mdm_execution_service::missing::ExecutionError::MissingOperation => Missing::Operation, rss_mdm_execution_service::missing::ExecutionError::MissingTask => Missing::Task }),
            E::Publication(e) => Self::Missing(match e { rss_mdm_software_service::management::publication::error::PublicationError::MissingSource => Missing::SoftwareSource, rss_mdm_software_service::management::publication::error::PublicationError::MissingPublication => Missing::SoftwarePublication }),
            E::Configuration(c) => Self::Unavailable(Failure::ExecutionConfiguration(c)),
            E::Unavailable(f) => Self::Unavailable(match f {
                rss_mdm_execution_service::Failure::RequestDeadline => Failure::RequestDeadline,
                rss_mdm_execution_service::Failure::Audit => Failure::Audit,
                rss_mdm_execution_service::Failure::AuditIntegrity => Failure::AuditIntegrity,
                rss_mdm_execution_service::Failure::AuditAdmission => Failure::AuditAdmission,
                rss_mdm_execution_service::Failure::AuditIsolation => Failure::AuditIsolation,
                rss_mdm_execution_service::Failure::AuditContract => Failure::AuditContract,


                other => Failure::Execution(other),
            }),
        }
    }
}
impl From<Error> for rss_mdm_execution_service::channels::Rejection {
    fn from(e: Error) -> Self {
        use rss_mdm_execution_service::channels::Rejection as R;
        match e {
            Error::CommitUnknown => R::CommitUnknown,
            Error::RollbackFailed => R::RollbackFailed,
            Error::Malformed | Error::CertificateRequest => R::Malformed,
            Error::Unauthorized => R::Unauthorized,
            Error::Forbidden => R::Forbidden,
            Error::Conflict => R::Conflict,
            Error::Unavailable(Failure::RequestDeadline) => R::Deadline,
            Error::Unavailable(Failure::Audit) => R::Audit,
            Error::Unavailable(Failure::AuditIntegrity) => R::AuditIntegrity,
            Error::Unavailable(Failure::AuditAdmission) => R::AuditAdmission,
            Error::Unavailable(Failure::AuditIsolation) => R::AuditIsolation,
            Error::Unavailable(Failure::AuditContract) => R::AuditContract,

            Error::Unavailable(Failure::Protocol) => R::Protocol,
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
        match e {
            rss_mdm_apple_mdm::Error::Malformed => Self::Malformed,
            rss_mdm_apple_mdm::Error::Unsupported => Self::Unsupported,
            rss_mdm_apple_mdm::Error::Conflict => Self::Conflict,
        }
    }
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        use axum::Json;
        let code = match &self {
            Self::Malformed => Code::MalformedRequest,
            Self::CertificateRequest => Code::InvalidCertificateRequest,
            Self::Unauthorized => Code::InvalidIdentity,
            Self::Forbidden => Code::PermissionDenied,
            Self::Conflict => Code::OperationConflict,
            Self::EnrollmentPaused => Code::EnrollmentPaused,
            Self::CommitUnknown => Code::OperationUnknown,
            Self::RollbackFailed => Code::OperationRollbackUnconfirmed,
            Self::NotFound => Code::InventoryNotFound,
            Self::Missing(m) => m.code(),
            Self::Unsupported => Code::ActionNotSupported,
            Self::Unavailable(Failure::AuditIntegrity) => Code::AuditIntegrityError,
            Self::Unavailable(
                Failure::AuditAdmission | Failure::AuditIsolation | Failure::AuditContract,
            ) => Code::AuditContractError,
            Self::Unavailable(_) | Self::Configuration(_) => Code::ServiceUnavailable,
        };
        let mut response = (code.status(), Json(ErrorBody { code })).into_response();
        if matches!(self, Self::EnrollmentPaused) {
            response
                .extensions_mut()
                .insert(rss_mdm_agent_wire::enroll::ErrorBody {
                    code: rss_mdm_agent_wire::enroll::ErrorCode::EnrollmentPaused,
                    issuance_id: None,
                });
        }
        response.extensions_mut().insert(self);
        response
    }
}

impl From<rss_mdm_pki_service::Error> for Error {
    fn from(error: rss_mdm_pki_service::Error) -> Self {
        match error {
            rss_mdm_pki_service::Error::Request => Self::Malformed,
            rss_mdm_pki_service::Error::Forbidden => Self::Unauthorized,
            _ => Self::Unavailable(crate::Failure::Database),
        }
    }
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Code {
    MalformedRequest,
    InvalidCertificateRequest,
    InvalidIdentity,
    PermissionDenied,
    OperationConflict,
    EnrollmentPaused,
    OperationUnknown,
    InventoryNotFound,
    ActionNotSupported,
    AuditIntegrityError,
    AuditContractError,
    ServiceUnavailable,
    OperationRollbackUnconfirmed,
    ResourceNotFound,
    OperationNotFound,
    TaskNotFound,
    SoftwareSourceNotFound,
    SoftwarePublicationNotFound,
}
impl Code {
    fn status(self) -> axum::http::StatusCode {
        match self {
            Self::MalformedRequest => axum::http::StatusCode::BAD_REQUEST,
            Self::InvalidCertificateRequest => axum::http::StatusCode::BAD_REQUEST,
            Self::InvalidIdentity => axum::http::StatusCode::UNAUTHORIZED,
            Self::PermissionDenied => axum::http::StatusCode::FORBIDDEN,
            Self::OperationConflict => axum::http::StatusCode::CONFLICT,
            Self::EnrollmentPaused => axum::http::StatusCode::CONFLICT,
            Self::OperationUnknown => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Self::InventoryNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::ActionNotSupported => axum::http::StatusCode::NOT_IMPLEMENTED,
            Self::AuditIntegrityError => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::AuditContractError => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Self::OperationRollbackUnconfirmed => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Self::ResourceNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::OperationNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::TaskNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::SoftwareSourceNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::SoftwarePublicationNotFound => axum::http::StatusCode::NOT_FOUND,
        }
    }
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct ErrorBody {
    code: Code,
}
impl rss_mdm_http_contract::signature::Output for Error {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        let codes = rss_mdm_http_contract::signature::Schema::response::<Code>();
        codes
            .string_values()
            .iter()
            .map(|value| {
                let code: Code = serde_json::from_value(value.clone()).expect("derived error code");
                let mut response = rss_mdm_http_contract::signature::Response::json::<ErrorBody>(
                    code.status().as_u16(),
                );
                response
                    .body
                    .as_mut()
                    .expect("JSON error body")
                    .schema
                    .value["properties"]["code"] =
                    serde_json::json!({"type":"string","const":value});
                response
            })
            .collect()
    }
}
