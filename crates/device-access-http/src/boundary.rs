//! Bounded independent ingress with the shared Identity and request-audit owners.
use crate::{Error, Services};
use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderValue, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rss_mdm_audit_integration::{
    AuditIntent, RequestAudit,
    completion::{Replacement, complete},
};
use rss_mdm_authorization_service::{context::AuthorizedPrincipal, credential::RequestCredential};
use std::{sync::Arc, time::Duration};
pub struct Administrator(pub AuthorizedPrincipal);
impl FromRequestParts<Arc<Services>> for Administrator {
    type Rejection = Error;
    async fn from_request_parts(parts: &mut Parts, s: &Arc<Services>) -> Result<Self, Error> {
        if parts.headers.contains_key(header::COOKIE)
            || parts.headers.get_all(header::AUTHORIZATION).iter().count() != 1
        {
            return Err(Error::Unauthorized);
        }
        let raw = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(Error::Unauthorized)?;
        let secret = rss_identity_core::session::BearerSecret::parse(raw.to_owned())
            .map_err(|_| Error::Unauthorized)?;
        let p = s
            .sessions
            .authenticate(&s.authorization, RequestCredential::Bearer(secret))
            .await?;
        let audit = parts
            .extensions
            .get::<RequestAudit>()
            .ok_or(Error::Unavailable)?;
        p.bind_audit(audit)?;
        Ok(Self(p))
    }
}
impl rss_mdm_http_contract::signature::Input for Administrator {
    fn request() -> rss_mdm_http_contract::signature::Request {
        use rss_mdm_http_contract::signature::{Request, Schema};
        Request {
            headers: [("authorization".into(), Schema::request::<String>())].into(),
            required_headers: vec!["authorization"],
            ..Request::default()
        }
    }
}
pub async fn admit(State(s): State<Arc<Services>>, mut request: Request, next: Next) -> Response {
    let a = RequestAudit::new(
        rss_mdm_install_support::StorageProfile::Da,
        s.sessions.tenant().to_string(),
        "da_http",
        AuditIntent::Routine,
    );
    let permit = match s.requests.clone().try_acquire_owned() {
        Ok(v) => v,
        Err(_) => {
            a.finalize(None);
            return Error::Unavailable.into_response();
        }
    };
    let invalid = request.headers().get_all(header::HOST).iter().count() != 1
        || request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(s.host.as_str())
        || request.uri().to_string().len() > 8192
        || request.headers().contains_key("x-client-certificate")
        || request.headers().contains_key("x-ssl-client-cert")
        || request.headers().contains_key(header::COOKIE);
    request.extensions_mut().insert(a.clone());
    // Completion retains the admission lease even if the HTTP client disconnects.
    tokio::spawn(async move {
        let _permit = permit;
        let mut response = if invalid {
            Error::Malformed.into_response()
        } else {
            match tokio::time::timeout(Duration::from_secs(12), next.run(request)).await {
                Ok(v) => v,
                Err(_) => Error::Classified(
                    rss_mdm_audit_integration::completion::ResponseFailure::Deadline,
                )
                .into_response(),
            }
        };
        let failure = response
            .extensions()
            .get::<Error>()
            .and_then(Error::failure);
        if let Some(replacement) = complete(&s.audit, &a, response.status().as_u16(), failure).await
        {
            response = match replacement {
                Replacement::CommitUnknown => Error::Unknown,
                Replacement::RollbackFailed => Error::Rollback,
                Replacement::Audit(_) => Error::Unavailable,
            }
            .into_response();
        }
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.headers_mut().insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_str(&a.request_id().to_string()).expect("UUID"),
        );
        response
    })
    .await
    .unwrap_or_else(|_| Error::Unknown.into_response())
}
