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
    pub http: rss_identity_web_credentials::HttpConfig,
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
        activity: rss_identity_web_credentials::SessionActivity,
        access: &rss_mdm_authorization_service::Store,
        address: Option<std::net::IpAddr>,
        programmatic: bool,
        deadline: rss_request_context::Deadline,
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
            let (session, secret) = rss_identity_web_credentials::authenticate_bearer_request(
                &self.authority,
                &self.http,
                binding,
                headers,
                deadline,
            )
            .await
            .map_err(project_failure)?;
            return Ok((
                Principal::new(&self.authority, session, binding)
                    .map_err(Error::from)
                    .map_err(IntoResponse::into_response)?,
                RequestCredential::Bearer(secret),
            ));
        }
        let (session, credential) = rss_identity_web_credentials::authenticate_request(
            &self.authority,
            &self.http,
            binding,
            headers,
            activity,
            deadline,
        )
        .await
        .map_err(project_failure)?;
        let proof = Principal::new(&self.authority, session, binding)
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

fn project_failure(error: rss_identity_web_credentials::CredentialError) -> Response {
    let mut response = rss_mdm_identity_http::HttpError::from(error).into_response();
    // Preserve component settlement and expose its class to the product audit boundary.
    if let Some(rss_mdm_identity_http::HttpFailure::Authority(error)) = response
        .extensions()
        .get::<rss_mdm_identity_http::HttpFailure>()
        .copied()
    {
        response.extensions_mut().insert(failure(error));
    }
    response
}

pub struct Mount<'a> {
    pub identity: &'a Identity,
    pub federation: Option<&'a rss_identity_postgres::Federation>,
    pub management_tenant: rss_request_context::TenantId,
    pub admission: std::sync::Arc<crate::api_access::BearerAdmission>,
    pub envelope: crate::boundary::Envelope,
}
pub fn routes(
    runtime: Option<Mount<'_>>,
    oidc: bool,
) -> rss_mdm_http_contract::Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    use rss_mdm_identity_http as shared;
    let local = runtime.as_ref().map(|m| shared::AppState {
        authority: m.identity.authority.clone(),
        config: m.identity.http.clone(),
    });
    let federation = runtime
        .as_ref()
        .and_then(|m| m.federation)
        .zip(local.as_ref());
    let mut bearer = shared::bearer_routes(local.as_ref()).rejections(crate::boundary::rejections);
    let mut tenants = shared::federation_routes(federation)
        .rejections(crate::boundary::rejections)
        .rejections(|_, _| vec![rss_mdm_http_contract::signature::Response::empty(403)]);
    if let Some(m) = &runtime {
        bearer = bearer.route_layer(axum::middleware::from_fn_with_state(
            m.admission.clone(),
            crate::api_access::admit_bearer,
        ));
        tenants = tenants.route_layer(axum::middleware::from_fn_with_state(
            m.management_tenant,
            business_federation,
        ));
    }
    rss_mdm_http_contract::route_module! {struct ManagementIdentity for [Browser] {local,bearer,tenants [optional],callback [optional]}}
    let routes = ManagementIdentity {
        local: shared::local_routes(
            local
                .as_ref()
                .zip(runtime.as_ref().map(|m| &m.identity.webauthn)),
        )
        .rejections(crate::boundary::rejections),
        bearer,
        tenants: tenants.when("identity.oidc", oidc),
        callback: shared::callback_route(federation).when("identity.oidc", oidc),
    }
    .assemble();
    match runtime {
        Some(m) => routes.route_layer(axum::middleware::from_fn_with_state(
            m.envelope,
            crate::boundary::authentication,
        )),
        None => routes,
    }
}
async fn business_federation(
    axum::extract::State(management): axum::extract::State<rss_request_context::TenantId>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    match request.extensions().get::<ExecutionBinding>() {
        Some(binding) if binding.tenant() != management => next.run(request).await,
        _ => axum::http::StatusCode::FORBIDDEN.into_response(),
    }
}
