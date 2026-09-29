use crate::{Error, Failure};
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use rss_identity_core::session::SessionSecret;
use rss_identity_postgres::{Authority, AuthorityError};
use rss_mdm_authorization_service::context::Principal;
use rss_request_context::TenantId;
pub struct Identity {
    pub authority: Authority,
    pub http: rss_identity_http_axum::HttpConfig,
    pub tenant: TenantId,
}
fn deadline() -> rss_transactional_messaging::policy::OperationDeadline {
    rss_transactional_messaging::policy::OperationDeadline::from_remaining(
        std::time::Duration::from_secs(10),
    )
}
fn failure(e: AuthorityError) -> Error {
    match e {
        AuthorityError::Rejected | AuthorityError::ReauthenticationFailed => Error::Unauthorized,
        AuthorityError::CommitUnknown(_) => Error::CommitUnknown,
        AuthorityError::RollbackFailed(_) => Error::RollbackFailed,
        _ => Error::Unavailable(Failure::IdentityStorage),
    }
}
impl Identity {
    pub async fn authenticate_request(
        &self,
        headers: &HeaderMap,
        activity: rss_identity_http_axum::SessionActivity,
    ) -> Result<(Principal, SessionSecret), Response> {
        let (session, credential) = rss_identity_http_axum::authenticate_request(
            &self.authority,
            &self.http,
            self.tenant,
            headers,
            activity,
            deadline(),
        )
        .await
        .map_err(|mut response| {
            // Keep the component response and settlement class; product audit reads Error.
            if let Some(rss_identity_http_axum::HttpFailure::Authority(error)) = response
                .extensions()
                .get::<rss_identity_http_axum::HttpFailure>()
                .copied()
            {
                response.extensions_mut().insert(failure(error));
            }
            response
        })?;
        let proof = Principal::new(session)
            .map_err(Error::from)
            .map_err(IntoResponse::into_response)?;
        Ok((proof, credential))
    }
}
