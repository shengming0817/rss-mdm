//! DA ingress preserves business wire codes and Audit settlement classification.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::completion::ResponseFailure as Failure;
#[derive(Clone, Debug)]
pub enum Error {
    Malformed,
    RequestTooLarge,
    Unauthorized,
    Forbidden,
    Conflict,
    NotFound,
    Unsupported,
    CommitUnknown,
    RollbackFailed,
    Unavailable,
    CursorInvalidated,
    ReadConflict,
    RegistrationLimit,
    EnrollmentPaused,
    Classified(Failure),
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Body {
    code: &'static str,
}
impl Error {
    pub fn failure(&self) -> Option<Failure> {
        match self {
            Self::CommitUnknown => Some(Failure::CommitUnknown),
            Self::RollbackFailed => Some(Failure::RollbackFailed),
            Self::Unauthorized => Some(Failure::Denied),
            Self::Forbidden => Some(Failure::Forbidden),
            Self::Classified(f) => Some(*f),
            _ => None,
        }
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Malformed => (400, "malformed_request"),
            Self::RequestTooLarge => (413, "request_too_large"),
            Self::Unauthorized => (401, "invalid_identity"),
            Self::Forbidden => (403, "permission_denied"),
            Self::Conflict => (409, "operation_conflict"),
            Self::NotFound => (404, "inventory_not_found"),
            Self::Unsupported => (400, "action_not_supported"),
            Self::CommitUnknown => (503, "operation_unknown"),
            Self::RollbackFailed => (503, "operation_rollback_unconfirmed"),
            Self::Unavailable | Self::Classified(_) => (503, "service_unavailable"),
            Self::CursorInvalidated => (409, "query_cursor_invalidated"),
            Self::ReadConflict => (409, "query_read_conflict"),
            Self::RegistrationLimit => (409, "registration_limit"),
            Self::EnrollmentPaused => (409, "enrollment_paused"),
        };
        let mut response = (
            StatusCode::from_u16(status).expect("fixed status"),
            Json(Body { code }),
        )
            .into_response();
        if let Some(f) = self.failure() {
            response.extensions_mut().insert(f);
        }
        response.extensions_mut().insert(self);
        response
    }
}
impl rss_mdm_http_contract::signature::Output for Error {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        [400, 401, 403, 404, 409, 413, 503]
            .into_iter()
            .map(rss_mdm_http_contract::signature::Response::json::<Body>)
            .collect()
    }
}
impl From<rss_mdm_device_access_postgres::Error> for Error {
    fn from(e: rss_mdm_device_access_postgres::Error) -> Self {
        use rss_mdm_device_access_postgres::Error as E;
        match e {
            E::Signing(e) => match crate::Error::from(e).failure() {
                Some(f) => Self::Classified(f),
                None => Self::Unavailable,
            },
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::NotFound => Self::NotFound,
            E::Unsupported => Self::Unsupported,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::CursorInvalidated => Self::CursorInvalidated,
            E::ReadConflict => Self::ReadConflict,
            E::RegistrationLimit => Self::RegistrationLimit,
            E::EnrollmentPaused => Self::EnrollmentPaused,
            E::Deadline => Self::Classified(Failure::Deadline),
            E::Audit(e) => e.as_ref().into(),
            E::Agent(_) => Self::Unauthorized,
            E::Corrupt
            | E::Storage
            | E::Capacity
            | E::Runtime
            | E::Retirement
            | E::Configuration => Self::Unavailable,
        }
    }
}
impl From<&rss_mdm_audit_integration::Error> for Error {
    fn from(e: &rss_mdm_audit_integration::Error) -> Self {
        use rss_mdm_audit_integration::ErrorClass as C;
        match e.class() {
            C::CommitUnknown => Self::CommitUnknown,
            C::RollbackFailed => Self::RollbackFailed,
            C::RequestDeadline => Self::Classified(Failure::Deadline),
            C::AuditIntegrity => Self::Classified(Failure::AuditIntegrity),
            C::AuditContract | C::AuditAdmission | C::AuditIsolation => {
                Self::Classified(Failure::AuditContract)
            }
            C::Audit => Self::Classified(Failure::AuditUnavailable),
        }
    }
}
impl From<rss_mdm_registration_service::Error> for Error {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        rss_mdm_device_access_postgres::Error::from(e).into()
    }
}
impl From<rss_mdm_authorization_service::Error> for Error {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        rss_mdm_device_access_postgres::Error::from(e).into()
    }
}
impl From<rss_mdm_authorization_service::error::AuthorizationError> for Error {
    fn from(e: rss_mdm_authorization_service::error::AuthorizationError) -> Self {
        rss_mdm_authorization_service::Error::from(e).into()
    }
}
impl From<rss_mdm_recovery_credentials::Error> for Error {
    fn from(e: rss_mdm_recovery_credentials::Error) -> Self {
        use rss_mdm_recovery_credentials::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::NotFound => Self::NotFound,
            E::CommitUnknown => Self::CommitUnknown,
            E::RollbackFailed => Self::RollbackFailed,
            E::Audit => Self::Classified(Failure::AuditUnavailable),
            E::CursorInvalidated => Self::CursorInvalidated,
            E::ReadConflict => Self::ReadConflict,
            _ => Self::Unavailable,
        }
    }
}
impl From<axum::extract::rejection::JsonRejection> for Error {
    fn from(e: axum::extract::rejection::JsonRejection) -> Self {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Self::RequestTooLarge
        } else {
            Self::Malformed
        }
    }
}
