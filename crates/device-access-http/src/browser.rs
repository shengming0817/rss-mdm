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
    pub vault: Arc<rss_mdm_vault_sync::Service>,
    pub identity: Arc<Identity>,
    pub authorization: Arc<rss_mdm_authorization_service::Store>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub business: Arc<crate::device_access::Services>,
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
    rss_mdm_http_contract::route_module! {struct Protected for [Browser]{management at "/api/v1",vault,platform}}
    let mut protected = Protected {
        vault: crate::vault::routes(state.map(|s| s.vault.clone())),
        management,
        platform: crate::platform_sso::management_routes().bind_with(platform.as_ref(), Arc::clone),
    }
    .assemble();
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
async fn authenticate(
    State(s): State<Arc<Services>>,
    mut request: Request,
    next: Next,
) -> Response {
    let activity = if matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) {
        rss_identity_http_axum::SessionActivity::Passive
    } else {
        rss_identity_http_axum::SessionActivity::Active
    };
    let authenticated = rss_identity_http_axum::authenticate_request(
        &s.identity.authority,
        &s.identity.http,
        s.identity.tenant,
        request.headers(),
        activity,
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(
            Duration::from_secs(10),
        ),
    )
    .await;
    let session = match authenticated {
        Ok((s, _)) => s,
        Err(r) => return r,
    };
    let audit = request.extensions().get::<RequestAudit>().cloned();
    let result = async {
        let principal = Principal::new(session)?;
        let proof = AuthorizedPrincipal::from_identity(s.authorization.profile(), principal);
        let audit = audit
            .as_ref()
            .ok_or(rss_mdm_authorization_service::Error::Storage)?;
        proof.bind_audit(audit)?;
        s.authorization
            .require_tenant_purpose(&proof, false)
            .await?;
        proof.load_authorization(&s.authorization).await
    }
    .await;
    match result {
        Ok(proof) => {
            request.extensions_mut().insert(RequestAuth {
                proof: Arc::new(proof),
            });
            next.run(request).await
        }
        Err(e) => Error::from(e).into_response(),
    }
}
/// Audit completion also covers the host's Identity routes, without trusting forwarded identity.
pub fn envelope(router: axum::Router, state: Arc<Services>) -> axum::Router {
    router
        .layer(axum::extract::DefaultBodyLimit::max(131072))
        .layer(axum::middleware::from_fn_with_state(state, admit))
}
async fn admit(State(s): State<Arc<Services>>, mut request: Request, next: Next) -> Response {
    let audit = RequestAudit::new(
        rss_mdm_audit_integration::Origin::Request,
        rss_mdm_install_support::StorageProfile::Da,
        s.identity.tenant.to_string(),
        "da_browser",
        AuditIntent::Routine,
    );
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
        if let Some(replacement) =
            complete(&s.audit, &audit, response.status().as_u16(), failure).await
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
