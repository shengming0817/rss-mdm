//! Reuse tenant rule handlers behind installation management admission.
//! ref: axum axum/src/routing/mod.rs@8762520da82cd99b78b35869069b36cfa305d4b9.
use crate::authorization::http::{self, AuthenticationState, HttpState};
use axum::{Router, middleware};
use std::sync::Arc;

pub fn router(
    authentication: Arc<AuthenticationState>,
    envelope: crate::boundary::Envelope,
) -> Router {
    let routes = Router::new()
        .nest(
            "/api/v1/tenant-administration",
            http::rule_routes().with_state(Arc::new(HttpState {
                audit_store: envelope.audit_store.clone(),
            })),
        )
        .route_layer(middleware::from_fn_with_state(
            authentication,
            http::protect_management,
        ));
    crate::boundary::wrap(routes, envelope)
}
