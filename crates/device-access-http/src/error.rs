use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rss_mdm_agent_wire::enroll::{ErrorBody, ErrorCode as Code};
use rss_mdm_audit_integration::completion::ResponseFailure as Failure;
#[derive(Clone, Debug)]
pub enum Error {
    Malformed,
    Unauthorized,
    Forbidden,
    Conflict,
    Unavailable,
    Unknown,
    Rollback,
    Classified(Failure),
    Enrollment(Code, Option<uuid::Uuid>, Option<Failure>),
}
impl Error {
    fn code(&self) -> Code {
        match self {
            Self::Malformed => Code::MalformedRequest,
            Self::Unauthorized => Code::InvalidIdentity,
            Self::Forbidden => Code::PermissionDenied,
            Self::Conflict => Code::OperationConflict,
            Self::Unavailable | Self::Rollback | Self::Classified(_) => Code::ServiceUnavailable,
            Self::Unknown => Code::ActivationUnknown,
            Self::Enrollment(c, _, _) => *c,
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
    pub(crate) fn failure(&self) -> Option<Failure> {
        match self {
            Self::Classified(f) | Self::Enrollment(_, _, Some(f)) => Some(*f),
            Self::Unknown
            | Self::Enrollment(Code::ActivationUnknown | Code::IssuanceUnknown, _, None) => {
                Some(Failure::CommitUnknown)
            }
            Self::Rollback => Some(Failure::RollbackFailed),
            Self::Unauthorized => Some(Failure::Denied),
            Self::Forbidden => Some(Failure::Forbidden),
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
                    Self::Enrollment(_, id, _) => *id,
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
fn audit_class(e: &rss_mdm_audit_integration::Error) -> Failure {
    use rss_mdm_audit_integration::ErrorClass as C;
    match e.class() {
        C::CommitUnknown => Failure::CommitUnknown,
        C::RollbackFailed => Failure::RollbackFailed,
        C::RequestDeadline => Failure::Deadline,
        C::AuditIntegrity => Failure::AuditIntegrity,
        C::AuditContract | C::AuditIsolation | C::AuditAdmission => Failure::AuditContract,
        C::Audit => Failure::AuditUnavailable,
    }
}
impl From<rss_mdm_registration_service::agent::Failure> for Error {
    fn from(v: rss_mdm_registration_service::agent::Failure) -> Self {
        use rss_mdm_registration_service::Error as E;
        let failure = match v.source.as_ref() {
            Some(E::CommitUnknown) => Some(Failure::CommitUnknown),
            Some(E::RollbackFailed) => Some(Failure::RollbackFailed),
            Some(E::Deadline) => Some(Failure::Deadline),
            Some(E::Audit(e)) => Some(audit_class(e)),
            Some(E::Unauthorized) => Some(Failure::Denied),
            Some(E::Forbidden) => Some(Failure::Forbidden),
            _ => None,
        };
        Self::Enrollment(v.code, v.issuance_id, failure)
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
            E::Deadline => Self::Classified(Failure::Deadline),
            E::Audit(e) => Self::Classified(audit_class(&e)),
            _ => Self::Unavailable,
        }
    }
}
impl From<rss_mdm_task_trust::Error> for Error {
    fn from(v: rss_mdm_task_trust::Error) -> Self {
        use rss_mdm_task_trust::{Error as E, Failure as F};
        match v {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            // Private receipts reveal neither existence nor another scope's content.
            E::Forbidden | E::NotFound => Self::Forbidden,
            E::Conflict => Self::Conflict,
            E::CommitUnknown => Self::Unknown,
            E::RollbackFailed => Self::Rollback,
            E::Unavailable(F::AuditIntegrity) => Self::Classified(Failure::AuditIntegrity),
            E::Unavailable(F::AuditContract | F::AuditAdmission | F::AuditIsolation) => {
                Self::Classified(Failure::AuditContract)
            }
            E::Unavailable(F::Audit) => Self::Classified(Failure::AuditUnavailable),
            E::Unavailable(F::RequestDeadline) => Self::Classified(Failure::Deadline),
            _ => Self::Unavailable,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_projection_preserves_completion_classification() {
        use rss_mdm_task_trust::{Error as E, Failure as F};
        for (source, expected) in [
            (F::AuditIntegrity, Failure::AuditIntegrity),
            (F::AuditContract, Failure::AuditContract),
            (F::AuditAdmission, Failure::AuditContract),
            (F::AuditIsolation, Failure::AuditContract),
            (F::Audit, Failure::AuditUnavailable),
            (F::RequestDeadline, Failure::Deadline),
        ] {
            let projected = Error::from(E::Unavailable(source));
            assert_eq!(projected.failure(), Some(expected));
            assert_eq!(projected.status(), 503);
        }
        let registration = rss_mdm_registration_service::agent::Failure::from(
            rss_mdm_registration_service::Error::RollbackFailed,
        );
        assert_eq!(
            Error::from(registration).failure(),
            Some(Failure::RollbackFailed)
        );
        assert_eq!(
            Error::from(rss_mdm_authorization_service::Error::Deadline).failure(),
            Some(Failure::Deadline)
        );
        assert_eq!(Error::from(E::NotFound).status(), 403);
    }
}

impl From<rss_mdm_device_access_postgres::Error> for Error {
    fn from(e: rss_mdm_device_access_postgres::Error) -> Self {
        use rss_mdm_device_access_postgres::Error as E;
        match e {
            E::Malformed => Self::Malformed,
            E::Unauthorized => Self::Unauthorized,
            E::Forbidden | E::NotFound => Self::Forbidden,
            E::Conflict | E::ReadConflict | E::CursorInvalidated => Self::Conflict,
            E::CommitUnknown => Self::Unknown,
            E::RollbackFailed => Self::Rollback,
            E::Signing(e) => e.into(),
            E::Capacity => Self::Enrollment(Code::RegistrationLimit, None, None),
            E::Audit(e) => Self::Classified(audit_class(&e)),
            E::Deadline => Self::Classified(Failure::Deadline),
            _ => Self::Unavailable,
        }
    }
}
