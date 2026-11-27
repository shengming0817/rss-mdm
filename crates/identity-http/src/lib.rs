//! Shared Browser identity endpoints for the MDM and Device Access products.
//! ref: axum extract/state.rs @ c59208c86fded335cd85e388030ad59347b0e5ae.
mod bearer;
mod boundary;
pub mod challenge;
pub mod settlement;
mod transport;
pub use bearer::bearer_routes;
pub use challenge::TimedChallenge;
pub use dto::SessionBody;
pub use oidc::AuthorizationUrl;
pub use oidc::{authorization_redirect, callback_route, federation_routes, operation_actor};
pub use profiles::raw_profile_route;
pub use session::{issued_session_parts, local_routes};
pub use transport::CookieJson;
mod dto;
mod error;
mod oidc;
pub use oidc::protect_callback;
pub const CALLBACK_PATH: &str = "/api/v1/identity/oidc/callback";
mod accounts;
mod profiles;
mod providers;
mod session;
use axum::middleware;
pub use error::{HttpError, HttpFailure, credential_rejections};
use rss_identity_web_credentials::HttpConfig;

use rss_identity_postgres::{Authority, AuthorityError};

#[derive(Clone)]
pub struct AppState {
    pub authority: Authority,
    pub config: HttpConfig,
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn session_failure_classes_remain_internal_and_distinct() {
        use crate::boundary::{HttpError, HttpFailure};
        use axum::{body::to_bytes, response::IntoResponse};
        use rss_identity_postgres::{AuthorityError, StorageFailure};
        for error in [
            AuthorityError::RolledBack(StorageFailure::Transient),
            AuthorityError::CommitUnknown(StorageFailure::Transient),
            AuthorityError::RollbackFailed(StorageFailure::Transient),
            AuthorityError::Fenced,
            AuthorityError::Configuration,
            AuthorityError::DeadlineElapsed,
        ] {
            let response = HttpError::from(error).into_response();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(
                response.extensions().get::<HttpFailure>(),
                Some(&HttpFailure::Authority(error))
            );
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"code":"identity_unavailable"})
            );
        }
    }
}

/// Client attribution supplied by the hosting transport after its proxy trust check.
/// Required by password login, reauthentication and password changes. For direct TLS hosts,
/// map accepted Axum `ConnectInfo<SocketAddr>` to this extension in host middleware. Forwarded
/// headers are never interpreted by this adapter. The raw peer remains in `ConnectInfo`.
#[derive(Clone, Copy, Debug)]
pub struct ClientAddress(pub std::net::IpAddr);

mod webauthn;

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn request_budget_validates_finite_time_and_overflow() {
        for seconds in [120, 3600] {
            let duration = std::time::Duration::from_secs(seconds);
            assert!(HttpConfig::new("https://identity.example.test", duration).is_ok());
            assert!(
                boundary::request_deadline(
                    &axum::extract::Request::default(),
                    duration,
                    std::time::Instant::now()
                )
                .is_ok()
            );
        }
        for duration in [std::time::Duration::ZERO, std::time::Duration::MAX] {
            assert!(HttpConfig::new("https://identity.example.test", duration).is_err());
            assert!(
                boundary::request_deadline(
                    &axum::extract::Request::default(),
                    duration,
                    std::time::Instant::now()
                )
                .is_err()
            );
        }
    }
}

use rss_mdm_http_contract::{
    Category, Operation, QueryPolicy, Resource, Router,
    module::{Declaration, Route},
    route_module,
    routing::{get, post, put},
};
static IDENTITY: Resource = Resource {
    id: "identity_authentication",
    category: Category::Protocol,
    owner: "identity-http",
    proof: "foundation.authorization",
    query: QueryPolicy::Protocol,
    collection: None,
};
const ACTION: &[Operation] = &[Operation::Action];

fn browser<S: Clone + Send + Sync + 'static, M: Declaration>(
    routes: Router<S, M>,
    state: Option<&AppState>,
    limit: usize,
) -> Router<S, M> {
    let routes = routes
        .layer(axum::extract::DefaultBodyLimit::max(limit))
        .settles_transactions()
        .fixed_response_headers(&[
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
        ]);
    match state {
        Some(state) => routes.route_layer(middleware::from_fn_with_state(
            state.clone(),
            boundary::request_boundary,
        )),
        None => routes,
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use rss_mdm_http_contract::{artifact, module::Listener};
    #[test]
    fn all_identity_groups_export_their_registered_signatures() {
        fn check<M: Declaration>(routes: Router<(), M>, expected: usize) {
            let errors = routes.validate(Listener::Browser);
            assert!(errors.is_empty(), "{errors:#?}");
            assert_eq!(routes.endpoints().len(), expected);
            artifact::document([("browser", routes.into_endpoints())])
                .expect("valid exported identity endpoints");
        }
        check(local_routes(None), 25);
        check(bearer_routes(None), 2);
        check(federation_routes(None), 10);
        check(callback_route(None), 1);
        check(raw_profile_route(None), 1);
    }
}
