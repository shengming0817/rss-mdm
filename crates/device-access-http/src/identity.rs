use crate::business_error::Error;
use axum::http::HeaderMap;
use rss_identity_postgres::{Authority, AuthorityError};
use rss_request_context::TenantId;
pub struct Identity {
    pub enterprise_administrators: std::collections::BTreeMap<
        uuid::Uuid,
        std::sync::Arc<rss_mdm_device_access_postgres::enterprise::keycloak::Administrator>,
    >,
    pub enterprise_clients: std::collections::BTreeMap<
        String,
        std::sync::Arc<dyn rss_mdm_device_access_postgres::enterprise::broker::Client>,
    >,
    pub authority: Authority,
    pub webauthn: rss_identity_postgres::WebauthnAuthority,
    pub http: rss_identity_http_axum::HttpConfig,
    pub tenant: TenantId,
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(10),
    )
}
pub(crate) fn failure(e: AuthorityError) -> Error {
    match e {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::RuleRejected(
            rss_identity_core::account::AccountRuleError::InsufficientPrivilege
            | rss_identity_core::account::AccountRuleError::ReauthenticationRequired,
        ) => Error::Forbidden,
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Unavailable,
    }
}
impl Identity {
    /// Reborrow a request credential when a component ceremony requires an owned session proof.
    pub(crate) async fn ceremony_actor(
        &self,
        headers: &HeaderMap,
    ) -> Result<rss_identity_postgres::AuthenticatedSession, Error> {
        rss_identity_http_axum::authenticate_request(
            &self.authority,
            &self.http,
            self.tenant,
            headers,
            rss_identity_http_axum::SessionActivity::Active,
            deadline(),
        )
        .await
        .map(|(session, _)| session)
        .map_err(|response| {
            match response
                .extensions()
                .get::<rss_identity_http_axum::HttpFailure>()
            {
                Some(rss_identity_http_axum::HttpFailure::Authority(error)) => failure(*error),
                _ if response.status().is_server_error() => Error::Unavailable,
                _ => Error::Unauthorized,
            }
        })
    }
}
pub(crate) struct CeremonyHeaders(pub(crate) axum::http::HeaderMap);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for CeremonyHeaders {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.headers.clone()))
    }
}
impl rss_mdm_http_contract::signature::Input for CeremonyHeaders {
    fn request() -> rss_mdm_http_contract::signature::Request {
        use rss_mdm_http_contract::signature::{Direction, Request, Schema};
        Request { headers:[("cookie".into(), Schema { direction: Direction::Request, value: serde_json::json!({"type":"string", "description":"Identity session cookie; validated by Identity Active authentication"}) }), ("origin".into(), Schema { direction: Direction::Request, value: serde_json::json!({"type":"string", "format":"uri"}) }), ("x-identity-request".into(), Schema { direction: Direction::Request, value: serde_json::json!({"type":"string", "const":"1"}) }), ("x-csrf-token".into(), Schema { direction: Direction::Request, value: serde_json::json!({"type":"string"}) })].into(), required_headers:vec!["cookie", "origin", "x-identity-request", "x-csrf-token"], ..Request::default() }
    }
}
