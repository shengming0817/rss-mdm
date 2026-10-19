//! Reuse tenant rule handlers behind installation management admission.
//! ref: axum axum/src/routing/mod.rs@8762520da82cd99b78b35869069b36cfa305d4b9.
use crate::authorization::http::{self, AuthenticationState, HttpState};
use axum::{Router, middleware};
use std::sync::Arc;

pub fn router(
    authentication: Arc<AuthenticationState>,
    registry: Router,
    settings: Arc<dyn crate::settings::Source>,
    policy: Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
    envelope: crate::boundary::Envelope,
) -> Router {
    let routes = Router::new()
        .nest(
            "/api/v1/tenant-administration",
            http::rule_routes()
                .with_state(Arc::new(HttpState {
                    audit_store: envelope.audit_store.clone(),
                }))
                .merge(crate::api_access::network_routes(Arc::new(
                    crate::api_access::Management {
                        access: authentication.access.clone(),
                        audit: envelope.audit_store.clone(),
                    },
                )))
                .merge(registry)
                .route(
                    "/settings/catalog",
                    axum::routing::get(crate::settings::platform).layer(axum::Extension(settings)),
                ),
        )
        .route_layer(middleware::from_fn_with_state(
            authentication.clone(),
            http::protect_management,
        ));
    let context =
        crate::router::management_identity_context(authentication, policy, &envelope.tenant);
    crate::boundary::wrap(routes.merge(context), envelope)
}
