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
    pub federation: Option<rss_identity_postgres::Federation>,
    pub excluded_federation_tenant: Option<TenantId>,
    pub authority: Authority,
    pub webauthn: rss_identity_postgres::WebauthnAuthority,
    pub http: rss_identity_web_credentials::HttpConfig,
    pub storage: rss_transactional_messaging::fence::StorageIdentity,
    pub expected_epoch: rss_transactional_messaging::fence::Epoch,
    pub rp_generation: rss_identity_postgres::RpGeneration,
}
pub(crate) fn failure(e: AuthorityError) -> Error {
    match e {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::RuleRejected(
            rss_identity_core::account::AccountRuleError::InsufficientPrivilege
            | rss_identity_core::account::AccountRuleError::ReauthenticationRequired,
        ) => Error::Forbidden,
        AuthorityError::DeadlineElapsed => {
            Error::Classified(rss_mdm_audit_integration::completion::ResponseFailure::Deadline)
        }
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Unavailable,
    }
}
impl Identity {
    pub fn execution(
        &self,
        tenant: TenantId,
    ) -> rss_transactional_messaging::fence::ExecutionBinding {
        rss_transactional_messaging::fence::ExecutionBinding::new(
            self.storage,
            tenant,
            self.expected_epoch,
        )
    }
    /// Reborrow a request credential when a component ceremony requires an owned session proof.
    pub(crate) async fn ceremony_actor(
        &self,
        binding: rss_transactional_messaging::fence::ExecutionBinding,
        headers: &HeaderMap,
        deadline: rss_request_context::Deadline,
    ) -> Result<rss_identity_postgres::AuthenticatedSession, Error> {
        rss_identity_web_credentials::authenticate_request(
            &self.authority,
            &self.http,
            binding,
            headers,
            rss_identity_web_credentials::SessionActivity::Active,
            deadline,
        )
        .await
        .map(|(session, _)| session)
        .map_err(|error| match error {
            rss_identity_web_credentials::CredentialError::Authority(error) => failure(error),
            rss_identity_web_credentials::CredentialError::Deadline => {
                Error::Classified(rss_mdm_audit_integration::completion::ResponseFailure::Deadline)
            }
            _ => Error::Unauthorized,
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

fn scope_rejections(_: &str, path: &str) -> Vec<rss_mdm_http_contract::signature::Response> {
    use rss_mdm_http_contract::signature::{Output, Response};
    if path == rss_mdm_identity_http::CALLBACK_PATH {
        return Vec::new();
    }
    let mut responses = vec![Response::empty(400), Response::empty(403)];
    responses.extend(
        Error::responses()
            .into_iter()
            .filter(|r| matches!(r.status, 400 | 413 | 503)),
    );
    responses
}
pub fn routes(
    state: Option<&Identity>,
    oidc: bool,
) -> rss_mdm_http_contract::Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    use rss_mdm_identity_http as shared;
    let local = state.map(|s| shared::AppState {
        authority: s.authority.clone(),
        config: s.http.clone(),
    });
    let federation = state
        .and_then(|s| s.federation.as_ref())
        .zip(local.as_ref());
    rss_mdm_http_contract::route_module! {struct DaIdentity for [Browser]{local,bearer,profile,tenants [optional],callback [optional]}}
    DaIdentity {
        local: shared::local_routes(local.as_ref().zip(state.map(|s| &s.webauthn))),
        bearer: shared::bearer_routes(local.as_ref()),
        profile: shared::raw_profile_route(local.as_ref()),
        tenants: shared::federation_routes(federation).when("oidc", oidc),
        callback: shared::callback_route(federation).when("oidc", oidc),
    }
    .assemble()
    .rejections(scope_rejections)
}
