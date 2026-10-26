use crate::{Error, Failure};
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use rss_identity_postgres::{Authority, AuthorityError};
use rss_mdm_authorization_service::context::Principal;
use rss_mdm_authorization_service::credential::{ApiKeySecret, RequestCredential};
use rss_request_context::TenantId;
pub struct Identity {
    pub enterprise_administrators: std::collections::BTreeMap<
        uuid::Uuid,
        std::sync::Arc<rss_mdm_registration_service::enterprise::keycloak::Administrator>,
    >,
    pub enterprise_clients: std::collections::BTreeMap<
        String,
        std::sync::Arc<dyn rss_mdm_registration_service::enterprise::broker::Client>,
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
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Unavailable(Failure::IdentityStorage),
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
                _ if response.status().is_server_error() => {
                    Error::Unavailable(Failure::IdentityStorage)
                }
                _ => Error::Unauthorized,
            }
        })
    }
    pub async fn authenticate_request(
        &self,
        headers: &HeaderMap,
        activity: rss_identity_http_axum::SessionActivity,
        access: &rss_mdm_authorization_service::Store,
        address: Option<std::net::IpAddr>,
        programmatic: bool,
    ) -> Result<(Principal, RequestCredential), Response> {
        let bearer = headers.contains_key("authorization");
        let key = headers.contains_key("x-api-key");
        if bearer || key {
            if bearer && key
                || headers.get_all("authorization").iter().count() > 1
                || headers.get_all("x-api-key").iter().count() > 1
                || has_identity_cookie(headers)
            {
                return Err(Error::Malformed.into_response());
            }
            if !programmatic {
                return Err(Error::Forbidden.into_response());
            }
            let address = address.ok_or_else(|| Error::Forbidden.into_response())?;
            access
                .require_api_source(address)
                .await
                .map_err(Error::from)
                .map_err(IntoResponse::into_response)?;
            if key {
                let raw = headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| Error::Unauthorized.into_response())?;
                let secret = ApiKeySecret::parse(raw.into())
                    .map_err(Error::from)
                    .map_err(IntoResponse::into_response)?;
                let proof = access
                    .authenticate_key(&self.tenant.to_string(), &secret)
                    .await
                    .map_err(Error::from)
                    .map_err(IntoResponse::into_response)?;
                return Ok((proof, RequestCredential::ApiKey(secret)));
            }
            let (session, secret) = rss_identity_http_axum::authenticate_bearer_request(
                &self.authority,
                &self.http,
                self.tenant,
                headers,
                deadline(),
            )
            .await
            .map_err(project_failure)?;
            return Ok((
                Principal::new(session)
                    .map_err(Error::from)
                    .map_err(IntoResponse::into_response)?,
                RequestCredential::Bearer(secret),
            ));
        }
        let (session, credential) = rss_identity_http_axum::authenticate_request(
            &self.authority,
            &self.http,
            self.tenant,
            headers,
            activity,
            deadline(),
        )
        .await
        .map_err(project_failure)?;
        let proof = Principal::new(session)
            .map_err(Error::from)
            .map_err(IntoResponse::into_response)?;
        Ok((proof, RequestCredential::Cookie(credential)))
    }
}

fn has_identity_cookie(headers: &HeaderMap) -> bool {
    headers.get_all("cookie").iter().any(|value| {
        value.to_str().map_or(true, |value| {
            value.split(';').any(|part| {
                part.trim().split_once('=').is_none_or(|(name, _)| {
                    name == "__Host-identity-session" || name == "__Host-identity-csrf"
                })
            })
        })
    })
}

fn project_failure(mut response: Response) -> Response {
    // Preserve component settlement and expose its class to the product audit boundary.
    if let Some(rss_identity_http_axum::HttpFailure::Authority(error)) = response
        .extensions()
        .get::<rss_identity_http_axum::HttpFailure>()
        .copied()
    {
        response.extensions_mut().insert(failure(error));
    }
    response
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
