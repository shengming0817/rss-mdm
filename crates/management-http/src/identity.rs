use crate::{Error, Failure};
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use rss_identity_postgres::{Authority, AuthorityError};
use rss_mdm_authorization_service::context::Principal;
use rss_mdm_authorization_service::credential::{ApiKeySecret, RequestCredential};
use rss_transactional_messaging::fence::ExecutionBinding;
pub struct Identity {
    pub authority: Authority,
    pub webauthn: rss_identity_postgres::WebauthnAuthority,
    pub http: rss_identity_http_axum::HttpConfig,
    pub rp_generation: rss_identity_postgres::RpGeneration,
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
        _ => Error::Unavailable(Failure::IdentityStorage),
    }
}
impl Identity {
    #[allow(
        clippy::too_many_arguments,
        reason = "keep execution scope and existing operation inputs explicit"
    )]
    pub async fn authenticate_request(
        &self,
        binding: ExecutionBinding,
        headers: &HeaderMap,
        activity: rss_identity_http_axum::SessionActivity,
        access: &rss_mdm_authorization_service::Store,
        address: Option<std::net::IpAddr>,
        programmatic: bool,
        deadline: rss_transactional_messaging::policy::OperationDeadline,
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
                    .authenticate_key(binding, &secret)
                    .await
                    .map_err(Error::from)
                    .map_err(IntoResponse::into_response)?;
                return Ok((proof, RequestCredential::ApiKey(secret)));
            }
            let (session, secret) = rss_identity_http_axum::authenticate_bearer_request(
                &self.authority,
                &self.http,
                binding,
                headers,
                deadline,
            )
            .await
            .map_err(project_failure)?;
            return Ok((
                Principal::new(session, binding)
                    .map_err(Error::from)
                    .map_err(IntoResponse::into_response)?,
                RequestCredential::Bearer(secret),
            ));
        }
        let (session, credential) = rss_identity_http_axum::authenticate_request(
            &self.authority,
            &self.http,
            binding,
            headers,
            activity,
            deadline,
        )
        .await
        .map_err(project_failure)?;
        let proof = Principal::new(session, binding)
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
