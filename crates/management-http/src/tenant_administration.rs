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
pub fn router<D0: rss_mdm_http_contract::module::Declaration>(
    authentication: Arc<AuthenticationState>,
    registry: Router<(), D0>,
    settings: Arc<dyn crate::settings::Source>,
    policy: Arc<Policy>,
    envelope: crate::boundary::Envelope,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<D0>> {
    let routes = assemble(
        Some((&authentication, &settings, &policy, &envelope, &cursor)),
        registry,
    );
    crate::boundary::wrap(routes, envelope)
}
pub fn contract_routes<D0: rss_mdm_http_contract::module::Declaration>(
    registry: Router<(), D0>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<D0>> {
    assemble(None, registry)
}
fn assemble<D0: rss_mdm_http_contract::module::Declaration>(
    runtime: Option<Runtime<'_>>,
    registry: Router<(), D0>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<D0>> {
    let context = runtime.as_ref();
    let platform_settings = {
 rss_mdm_http_contract::route_module! { struct AssembleModule1 for [Browser] { get_platform } }
 AssembleModule1 { get_platform: rss_mdm_http_contract::module::Route::new("/settings/catalog", rss_mdm_http_contract::routing::get(crate::settings::platform, &contracts::SETTINGS_CATALOG, &[RouteOperation::Get])) }.assemble()
}
        .bind_with(context, |(_, settings, _, _, _)| (*settings).clone());
    let routes = {
        rss_mdm_http_contract::route_module! { struct AssembleModule2 for [Browser] { api_v1_tenant_administration at "/api/v1/tenant-administration" } }
        AssembleModule2 { api_v1_tenant_administration: {
 rss_mdm_http_contract::route_module! { struct AssembleModule101 for [Browser] { base, api_access_register_network, registry [optional], platform_settings } }
 AssembleModule101 { base: http::rule_routes()
            .bind_with(context, |(_, _, _, envelope, cursor)| {
                Arc::new(HttpState {
                    cursor: (*cursor).clone(),
                    audit_store: envelope.audit_store.clone(),
                })
            }),
api_access_register_network: crate::api_access::register_network().bind_with(
                context,
                |(authentication, _, _, envelope, cursor)| {
                    Arc::new(crate::api_access::Management {
                        cursor: (*cursor).clone(),
                        access: authentication.access.clone(),
                        audit: envelope.audit_store.clone(),
                    })
                },
            ),
registry,
platform_settings }.assemble()
} }.assemble()
    };
    let routes = http::mount_protection(
        routes,
        runtime.map(|(authentication, _, _, _, _)| authentication.clone()),
        true,
    );
    {
        rss_mdm_http_contract::route_module! { struct AssembleModule102 for [Browser] { base, router_mount_management_identity_context } }
        AssembleModule102 {
            base: routes,
            router_mount_management_identity_context:
                crate::router::mount_management_identity_context(runtime.map(
                    |(authentication, _, policy, envelope, _)| {
                        (
                            authentication.clone(),
                            policy.clone(),
                            envelope.tenant.as_str(),
                        )
                    },
                )),
        }
        .assemble()
    }
}
