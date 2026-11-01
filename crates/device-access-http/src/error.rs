use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rss_mdm_agent_wire::enroll::{ErrorBody, ErrorCode as Code};
#[derive(Clone, Debug)]
pub enum Error {
    Malformed,
    Unauthorized,
    Forbidden,
    Conflict,
    Unavailable,
    Unknown,
    Rollback,
    Enrollment(Code, Option<uuid::Uuid>),
}
impl Error {
    fn code(&self) -> Code {
        match self {
            Self::Malformed => Code::MalformedRequest,
            Self::Unauthorized => Code::InvalidIdentity,
            Self::Forbidden => Code::PermissionDenied,
            Self::Conflict => Code::OperationConflict,
            Self::Unavailable | Self::Rollback => Code::ServiceUnavailable,
            Self::Unknown => Code::ActivationUnknown,
            Self::Enrollment(c, _) => *c,
        }
    }
    fn status(&self) -> StatusCode {
        match self.code() {
            Code::MalformedRequest => StatusCode::BAD_REQUEST,
            Code::InvalidIdentity
            | Code::CredentialRetired
            | Code::CredentialRevoked
            | Code::CertificateExpired => StatusCode::UNAUTHORIZED,
            Code::PermissionDenied | Code::GrantExpired | Code::GrantRevoked => {
                StatusCode::FORBIDDEN
            }
            Code::RegistrationLimit => StatusCode::TOO_MANY_REQUESTS,
            Code::EnrollmentPaused
            | Code::OperationConflict
            | Code::ConnectionDeploymentUnobserved
            | Code::ConnectionRetirementBlocked => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
    pub(crate) fn failure(&self) -> Option<rss_mdm_audit_integration::completion::ResponseFailure> {
        use rss_mdm_audit_integration::completion::ResponseFailure as F;
        match self {
            Self::Unknown
            | Self::Enrollment(Code::ActivationUnknown | Code::IssuanceUnknown, _) => {
                Some(F::CommitUnknown)
            }
            Self::Rollback => Some(F::RollbackFailed),
            Self::Unauthorized => Some(F::Denied),
            Self::Forbidden => Some(F::Forbidden),
            _ => None,
        }
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut response = (
            self.status(),
            Json(ErrorBody {
                code: self.code(),
                issuance_id: match &self {
                    Self::Enrollment(_, id) => *id,
                    _ => None,
                },
            }),
        )
            .into_response();
        response.extensions_mut().insert(self);
        response
    }
}
impl rss_mdm_http_contract::signature::Output for Error {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        [400, 401, 403, 409, 429, 503]
            .into_iter()
            .map(rss_mdm_http_contract::signature::Response::json::<ErrorBody>)
            .collect()
    }
}
impl From<rss_mdm_registration_service::agent::Failure> for Error {
    fn from(v: rss_mdm_registration_service::agent::Failure) -> Self {
        Self::Enrollment(v.code, v.issuance_id)
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(v: rss_mdm_authorization_service::Error) -> Self {
        use rss_mdm_authorization_service::Error as E;
        match v {
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::CommitUnknown => Self::Unknown,
            E::RollbackFailed => Self::Rollback,
            _ => Self::Unavailable,
        }
    }
}
impl From<rss_mdm_task_trust::Error> for Error {
    fn from(v: rss_mdm_task_trust::Error) -> Self {
        use rss_mdm_task_trust::Error as E;
        match v {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::Unknown,
            E::RollbackFailed => Self::Rollback,
            _ => Self::Unavailable,
        }
    }
}
