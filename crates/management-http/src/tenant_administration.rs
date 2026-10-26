//! Reuse tenant rule handlers behind installation management admission.
use crate::authorization::http::{self, AuthenticationState, HttpState};
use rss_mdm_http_contract::Router;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use std::sync::Arc;

type Policy = crate::authorization::identity_management::IdentityManagementPolicy;
type Runtime<'a> = (
    &'a Arc<AuthenticationState>,
    &'a Arc<dyn crate::settings::Source>,
    &'a Arc<Policy>,
    &'a crate::boundary::Envelope,
    &'a rss_mdm_query::cursor::CursorCodec,
);
pub fn router(
    authentication: Arc<AuthenticationState>,
    registry: Router,
    settings: Arc<dyn crate::settings::Source>,
    policy: Arc<Policy>,
    envelope: crate::boundary::Envelope,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router {
    let routes = assemble(
        Some((&authentication, &settings, &policy, &envelope, &cursor)),
        registry,
    );
    crate::boundary::wrap(routes, envelope)
}
pub fn contract_routes(registry: Router) -> Router {
    assemble(None, registry)
}
fn assemble(runtime: Option<Runtime<'_>>, registry: Router) -> Router {
    let context = runtime.as_ref();
    let platform_settings = Router::new()
        .route(
            "/settings/catalog",
            rss_mdm_http_contract::routing::get(crate::settings::platform)
                .owned(&contracts::SETTINGS_CATALOG, &[RouteOperation::Get]),
        )
        .bind_with(context, |(_, settings, _, _, _)| (*settings).clone());
    let routes = Router::new().nest(
        "/api/v1/tenant-administration",
        http::rule_routes()
            .bind_with(context, |(_, _, _, envelope, cursor)| {
                Arc::new(HttpState {
                    cursor: (*cursor).clone(),
                    audit_store: envelope.audit_store.clone(),
                })
            })
            .merge(crate::api_access::register_network().bind_with(
                context,
                |(authentication, _, _, envelope, cursor)| {
                    Arc::new(crate::api_access::Management {
                        cursor: (*cursor).clone(),
                        access: authentication.access.clone(),
                        audit: envelope.audit_store.clone(),
                    })
                },
            ))
            .merge(registry)
            .merge(platform_settings),
    );
    let routes = http::mount_protection(
        routes,
        runtime.map(|(authentication, _, _, _, _)| authentication.clone()),
        true,
    );
    routes.merge(crate::router::mount_management_identity_context(
        runtime.map(|(authentication, _, policy, envelope, _)| {
            (
                authentication.clone(),
                policy.clone(),
                envelope.tenant.as_str(),
            )
        }),
    ))
}
