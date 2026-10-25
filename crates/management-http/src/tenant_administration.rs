//! Reuse tenant rule handlers behind installation management admission.
//! ref: axum axum/src/routing/mod.rs@8762520da82cd99b78b35869069b36cfa305d4b9.
use crate::authorization::http::{self, AuthenticationState, HttpState};
use axum::middleware;
use rss_mdm_http_contract::Router;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use std::sync::Arc;

pub fn router(
    authentication: Arc<AuthenticationState>,
    registry: Router,
    settings: Arc<dyn crate::settings::Source>,
    policy: Arc<crate::authorization::identity_management::IdentityManagementPolicy>,
    envelope: crate::boundary::Envelope,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router {
    let routes = Router::new()
        .nest(
            "/api/v1/tenant-administration",
            http::rule_routes()
                .with_state(Arc::new(HttpState {
                    cursor: cursor.clone(),
                    audit_store: envelope.audit_store.clone(),
                }))
                .merge(crate::api_access::network_routes(Arc::new(
                    crate::api_access::Management {
                        cursor: cursor.clone(),
                        access: authentication.access.clone(),
                        audit: envelope.audit_store.clone(),
                    },
                )))
                .merge(registry)
                .route(
                    "/settings/catalog",
                    rss_mdm_http_contract::routing::get(crate::settings::platform)
                        .owned(&contracts::SETTINGS_CATALOG, &[RouteOperation::Get])
                        .layer(axum::Extension(settings)),
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
