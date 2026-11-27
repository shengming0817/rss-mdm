//! DA browser composition over one host-owned Identity authority.
//! ref: axum 0.8.9 axum/src/routing/mod.rs.
use crate::{business_error::Error, identity::Identity};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::{
    AuditIntent, RequestAudit,
    completion::{Replacement, complete},
};
use rss_mdm_authorization_service::context::{AuthorizedPrincipal, Principal, RequestAuth};
use rss_mdm_http_contract::{Router, module::Declaration};
use std::{sync::Arc, time::Duration};
pub struct Services {
    pub request_budget: rss_axum::RequestBudget,
    pub vault: Arc<rss_mdm_vault_sync::Service>,
    pub identity: Arc<Identity>,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub business: Arc<crate::device_access::Services>,
    pub management: Arc<crate::management::Services>,
    pub pki: Arc<crate::pki::HttpState>,
    pub platform: Arc<crate::platform_sso::HttpState>,
    pub origin: String,
    pub host: String,
    pub platform_configuration: serde_json::Value,
    pub requests: Arc<tokio::sync::Semaphore>,
}
pub fn router(state: Option<&Arc<Services>>) -> Router<(), impl Declaration + use<>> {
    let business = state.map(|s| s.business.clone());
    let platform = state.map(|s| s.platform.clone());
    rss_mdm_http_contract::route_module! {struct Management for [Browser]{access [optional],administration,pki}}
    let management = Management {
        access: crate::device_access::mount(business.clone(), true),
        administration: crate::administration::routes().bind_with(business.as_ref(), Arc::clone),
        pki: crate::pki::routes().bind_with(state.map(|s| &s.pki), Arc::clone),
    }
    .assemble();
    rss_mdm_http_contract::route_module! {struct Protected for [Browser]{management at "/api/v1/tenants/{tenant}",registration,inventory,vault,platform}}
    let mut protected = Protected {
        inventory: crate::configurations::standalone_inventory()
            .bind_with(state.map(|s| &s.management), Arc::clone),
        registration: crate::management::routes()
            .bind_with(state.map(|s| &s.management), Arc::clone),
        vault: crate::vault::routes(state.map(|s| s.vault.clone())),
        management,
        platform: crate::platform_sso::management_routes(
            platform
                .clone()
                .zip(business.as_ref().map(|s| s.registration.clone())),
        ),
    }
    .assemble()
    .authentication(authentication);
    if let Some(s) = state {
        protected = protected.layer(axum::middleware::from_fn_with_state(
            s.clone(),
            authenticate,
        ));
    }
    rss_mdm_http_contract::route_module! {struct Browser for [Browser]{protected,broker [optional],platform}}
    Browser {
        protected,
        broker: crate::enterprise_broker::mount(
            state.map(|s| {
                Arc::new(crate::enterprise_broker::Services {
                    registration: s.business.registration.clone(),
                    admission: s.business.admission.clone(),
                    identity: s.identity.clone(),
                    origin: s.origin.clone(),
                    platform_configuration: s.platform_configuration.clone(),
                })
            }),
            true,
        ),
        platform: crate::platform_sso::browser_routes().bind_with(platform.as_ref(), Arc::clone),
    }
    .assemble()
}
pub fn with_identity<M: rss_mdm_http_contract::module::Declaration>(
    state: Option<&Arc<Services>>,
    identity: Router<(), M>,
) -> Router<(), impl Declaration + use<M>> {
    rss_mdm_http_contract::route_module! {struct DaBrowser for [Browser]{product,identity}}
    DaBrowser {
        product: router(state),
        identity,
    }
    .assemble()
}
fn bearer_allowed(path: &str) -> bool {
    path.starts_with("/api/v1/tenants/{tenant}/da/")
        || path.ends_with("/apple/platform-sso/status")
        || path.contains("/device-access/credential-policies")
        || path.contains("/device-access/credential-operations")
        || path.ends_with("/device-access/materials")
}
fn authentication(method: &str, path: &str) -> rss_mdm_http_contract::authentication::Description {
    use rss_mdm_http_contract::signature::Output;
    rss_mdm_http_contract::authentication::Description {
        owner: "device-access-http::browser::authenticate",
        alternatives: rss_mdm_http_contract::authentication::identity_credentials(
            method,
            bearer_allowed(path),
            false,
        ),
        rejections: Error::responses()
            .into_iter()
            .chain(rss_mdm_http_contract::authentication::identity_rejections())
            .collect(),
        conditional_response_headers: vec![],
    }
}
async fn authenticate(
    State(s): State<Arc<Services>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(control) = request
        .extensions()
        .get::<rss_axum::RequestControl>()
        .cloned()
    else {
        return Error::Unavailable.into_response();
    };
    let activity = if matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) {
        rss_identity_web_credentials::SessionActivity::Passive
    } else {
        rss_identity_web_credentials::SessionActivity::Active
    };
    let Some(binding) = request
        .extensions()
        .get::<rss_transactional_messaging::fence::ExecutionBinding>()
        .copied()
    else {
        return Error::Malformed.into_response();
    };
    let deadline = control.deadline();
    let headers = request.headers();
    if headers.contains_key("x-api-key") {
        return Error::Forbidden.into_response();
    }
    let authenticated = if headers.contains_key("authorization") {
        let path = request
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .map(|v| v.as_str())
            .unwrap_or_default();
        if !bearer_allowed(path) {
            return Error::Forbidden.into_response();
        }
        let Some(address) = request
            .extensions()
            .get::<rss_mdm_identity_http::ClientAddress>()
        else {
            return Error::Forbidden.into_response();
        };
        if let Err(e) = s.authorization.require_api_source(address.0).await {
            return Error::from(e).into_response();
        }
        rss_identity_web_credentials::authenticate_bearer_request(
            &s.identity.authority,
            &s.identity.http,
            binding,
            headers,
            deadline,
        )
        .await
        .map(|(session, _)| session)
    } else {
        rss_identity_web_credentials::authenticate_request(
            &s.identity.authority,
            &s.identity.http,
            binding,
            headers,
            activity,
            deadline,
        )
        .await
        .map(|(session, _)| session)
    };
    let session = match authenticated {
        Ok(s) => s,
        Err(error) => return rss_mdm_identity_http::HttpError::from(error).into_response(),
    };
    let audit = request.extensions().get::<RequestAudit>().cloned();
    let deadline = control.deadline().instant();
    let result = tokio::time::timeout_at(deadline.into(), async {
        let principal = Principal::new(&s.identity.authority, session, binding)?;
        let proof = AuthorizedPrincipal::from_identity(&s.authorization, principal)?;
        let audit = audit
            .as_ref()
            .ok_or(rss_mdm_authorization_service::Error::Storage)?;
        proof.bind_audit(audit)?;
        s.authorization
            .require_tenant_purpose(&proof, false)
            .await?;
        proof.load_authorization(&s.authorization).await
    })
    .await
    .unwrap_or(Err(rss_mdm_authorization_service::Error::Deadline));
    match result {
        Ok(proof) => {
            request.extensions_mut().insert(RequestAuth {
                proof: Arc::new(proof),
                sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
                    s.identity.authority.clone(),
                ),
                deadline,
                cancellation: Arc::new(control),
            });
            tokio::time::timeout_at(deadline.into(), next.run(request))
                .await
                .unwrap_or_else(|_| {
                    Error::from(rss_mdm_authorization_service::Error::Deadline).into_response()
                })
        }
        Err(e) => Error::from(e).into_response(),
    }
}
/// Audit completion also covers the host's Identity routes, without trusting forwarded identity.
pub fn envelope(router: axum::Router, state: Arc<Services>) -> axum::Router {
    router
        .layer(axum::extract::DefaultBodyLimit::max(131072))
        .layer(axum::middleware::from_fn_with_state(state.clone(), admit))
        .layer(axum::middleware::from_fn_with_state(
            state.request_budget,
            rss_axum::request_control,
        ))
}
async fn admit(State(s): State<Arc<Services>>, mut request: Request, next: Next) -> Response {
    let locator = ["/api/v1/tenants/", "/api/v1/apple/platform-sso/"]
        .into_iter()
        .find_map(|prefix| {
            request
                .uri()
                .path()
                .strip_prefix(prefix)
                .and_then(|rest| rest.split('/').next())
        });
    let binding = locator
        .and_then(|tenant| rss_request_context::TenantId::parse(tenant).ok())
        .map(|tenant| s.identity.execution(tenant));
    let audit = match binding {
        Some(binding) => {
            request.extensions_mut().insert(binding);
            RequestAudit::new(
                rss_mdm_audit_integration::Origin::Request,
                rss_mdm_install_support::StorageProfile::Da,
                binding,
                "da_browser",
                AuditIntent::Routine,
            )
        }
        None => RequestAudit::unresolved(
            rss_mdm_audit_integration::Origin::Request,
            rss_mdm_install_support::StorageProfile::Da,
            "da_browser",
            AuditIntent::Routine,
        ),
    };
    let permit = match s.requests.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            audit.finalize(None);
            return Error::Unavailable.into_response();
        }
    };
    let invalid = request.headers().get_all("host").iter().count() != 1
        || request.headers().get("host").and_then(|h| h.to_str().ok()) != Some(s.host.as_str())
        || request.uri().to_string().len() > 8192
        || request.headers().contains_key("x-client-certificate")
        || request.headers().contains_key("x-ssl-client-cert");
    request.extensions_mut().insert(audit.clone());
    tokio::spawn(async move {
        let _permit = permit;
        let mut response = if invalid {
            Error::Malformed.into_response()
        } else {
            let (parts, body) = request.into_parts();
            match tokio::time::timeout(Duration::from_secs(5), axum::body::to_bytes(body, 131072))
                .await
            {
                Ok(Ok(body)) => {
                    next.run(Request::from_parts(parts, axum::body::Body::from(body)))
                        .await
                }
                failed => {
                    let mut response = if failed.is_err() {
                        Error::Classified(
                            rss_mdm_audit_integration::completion::ResponseFailure::Deadline,
                        )
                    } else {
                        Error::RequestTooLarge
                    }
                    .into_response();
                    response
                        .headers_mut()
                        .insert("connection", axum::http::HeaderValue::from_static("close"));
                    response
                }
            }
        };
        let failure = response
            .extensions()
            .get::<Error>()
            .and_then(Error::failure)
            .or_else(|| {
                response
                    .extensions()
                    .get::<rss_mdm_audit_integration::completion::ResponseFailure>()
                    .copied()
            });
        if let Some(replacement) = complete(
            &s.audit,
            &audit,
            response.status().as_u16(),
            failure,
            rss_request_context::Deadline::from_timeout(
                &rss_mdm_audit_integration::budget::RuntimeTimer,
                Duration::from_secs(2),
            )
            .expect("bounded DA settlement"),
        )
        .await
        {
            response = match replacement {
                Replacement::CommitUnknown => Error::CommitUnknown,
                Replacement::RollbackFailed => Error::RollbackFailed,
                Replacement::Audit(_) => Error::Unavailable,
            }
            .into_response()
        }
        response.headers_mut().insert(
            "cache-control",
            axum::http::HeaderValue::from_static("no-store"),
        );
        response.headers_mut().insert(
            "x-content-type-options",
            axum::http::HeaderValue::from_static("nosniff"),
        );
        response.headers_mut().insert(
            "x-request-id",
            axum::http::HeaderValue::from_str(&audit.request_id().to_string()).expect("UUID"),
        );
        response
    })
    .await
    .unwrap_or_else(|_| Error::CommitUnknown.into_response())
}
