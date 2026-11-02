//! Shared wire projection for Agent-protocol consumers; no product authentication or execution.
use crate::signature::{Direction, Input, Request, Response, Schema};
use axum::{
    Json,
    extract::FromRequestParts,
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response as HttpResponse},
};
use rss_mdm_agent_wire::runtime as wire;
use std::convert::Infallible;
/// The original headers passed to runtime device authentication, never a bearer identity.
pub struct RuntimeHeaders(pub HeaderMap);
impl<S: Send + Sync> FromRequestParts<S> for RuntimeHeaders {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl Input for RuntimeHeaders {
    fn request() -> Request {
        // authenticate() rejects any Authorization header; the peer certificate is transport-owned.
        Request {
            headers: [(
                "authorization".into(),
                Schema {
                    direction: Direction::Request,
                    value: false.into(),
                },
            )]
            .into(),
            ..Request::default()
        }
    }
}

pub fn status_for(code: wire::ErrorCode) -> StatusCode {
    match code {
        wire::ErrorCode::MalformedRequest
        | wire::ErrorCode::UnsupportedWire
        | wire::ErrorCode::UnsupportedCapability => StatusCode::BAD_REQUEST,
        wire::ErrorCode::InvalidIdentity
        | wire::ErrorCode::CredentialRevoked
        | wire::ErrorCode::CertificateExpired
        | wire::ErrorCode::CredentialRetired => StatusCode::UNAUTHORIZED,
        wire::ErrorCode::ActivityNotFound
        | wire::ErrorCode::CapabilityNotFound
        | wire::ErrorCode::ReportNotFound
        | wire::ErrorCode::TaskNotFound => StatusCode::NOT_FOUND,
        wire::ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
        wire::ErrorCode::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
        wire::ErrorCode::OperationConflict | wire::ErrorCode::ActivityCursorInvalidated => {
            StatusCode::CONFLICT
        }
        wire::ErrorCode::OperationUnknown | wire::ErrorCode::ServiceUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

pub fn credential_response(code: rss_mdm_agent_wire::enroll::ErrorCode) -> HttpResponse {
    use rss_mdm_agent_wire::enroll::ErrorCode as C;
    let code = match code {
        C::CredentialRevoked => wire::ErrorCode::CredentialRevoked,
        C::CertificateExpired => wire::ErrorCode::CertificateExpired,
        C::CredentialRetired => wire::ErrorCode::CredentialRetired,
        C::PermissionDenied => wire::ErrorCode::PermissionDenied,
        C::ServiceUnavailable | C::ActivationUnknown => wire::ErrorCode::ServiceUnavailable,
        _ => wire::ErrorCode::InvalidIdentity,
    };
    (status_for(code), Json(wire::ErrorBody { code })).into_response()
}

pub fn responses() -> Vec<Response> {
    let codes = Schema::response::<wire::ErrorCode>();
    codes
        .string_values()
        .iter()
        .map(|value| {
            let code: wire::ErrorCode =
                serde_json::from_value(value.clone()).expect("actual runtime error code");
            let mut response = Response::json::<wire::ErrorBody>(status_for(code).as_u16());
            response
                .body
                .as_mut()
                .expect("JSON error body")
                .schema
                .value["properties"]["code"]["const"] = value.clone();
            response
        })
        .collect()
}
