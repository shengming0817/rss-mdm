//! DA projects its business failures onto the retained Agent wire contract.
use crate::business_error::Error;
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use rss_mdm_agent_wire::runtime as wire;
#[derive(Clone)]
pub(crate) enum AgentError {
    Business(Error),
    Enrollment(rss_mdm_agent_wire::enroll::ErrorCode),
}
impl From<Error> for AgentError {
    fn from(e: Error) -> Self {
        Self::Business(e)
    }
}
impl From<rss_mdm_authorization_service::Error> for AgentError {
    fn from(e: rss_mdm_authorization_service::Error) -> Self {
        Self::Business(e.into())
    }
}
impl IntoResponse for AgentError {
    fn into_response(self) -> Response {
        let e = match self {
            Self::Business(error) => error,
            Self::Enrollment(code) => {
                return rss_mdm_http_contract::agent::credential_response(code);
            }
        };
        let code = match e {
            Error::Malformed | Error::RequestTooLarge => wire::ErrorCode::MalformedRequest,
            Error::Unauthorized | Error::Forbidden => wire::ErrorCode::InvalidIdentity,
            Error::Conflict
            | Error::ReadConflict
            | Error::CursorInvalidated
            | Error::EnrollmentPaused => wire::ErrorCode::OperationConflict,
            Error::CommitUnknown | Error::RollbackFailed => wire::ErrorCode::OperationUnknown,
            Error::NotFound => wire::ErrorCode::ReportNotFound,
            Error::Unsupported => wire::ErrorCode::UnsupportedCapability,
            Error::Unavailable | Error::RegistrationLimit | Error::Classified(_) => {
                wire::ErrorCode::ServiceUnavailable
            }
        };
        let mut response = (
            rss_mdm_http_contract::agent::status_for(code),
            Json(wire::ErrorBody { code }),
        )
            .into_response();
        response.extensions_mut().insert(wire::ErrorBody { code });
        if let Some(failure) = e.failure() {
            response.extensions_mut().insert(failure);
        }
        response.extensions_mut().insert(e);
        response
    }
}
impl rss_mdm_http_contract::signature::Output for AgentError {
    fn responses() -> Vec<rss_mdm_http_contract::signature::Response> {
        rss_mdm_http_contract::agent::responses()
    }
}
pub(crate) async fn bounded<T>(
    work: impl std::future::Future<Output = Result<T, AgentError>>,
) -> Result<T, AgentError> {
    tokio::time::timeout(std::time::Duration::from_secs(8), work)
        .await
        .map_err(|_| {
            AgentError::Business(Error::Classified(
                rss_mdm_audit_integration::completion::ResponseFailure::Deadline,
            ))
        })?
}
