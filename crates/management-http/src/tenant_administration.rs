//! Reuse tenant rule handlers behind installation management admission.
use crate::authorization::http::{self, AuthenticationState, HttpState};
use rss_mdm_http_contract::Router;
use std::sync::Arc;

type Policy = crate::authorization::identity_management::IdentityManagementPolicy;
type Runtime<'a> = (
    &'a Arc<AuthenticationState>,
    &'a Arc<Policy>,
    &'a crate::boundary::Envelope,
    &'a rss_mdm_query::cursor::CursorCodec,
);
#[allow(
    clippy::too_many_arguments,
    reason = "keep execution scope and existing operation inputs explicit"
)]
pub fn router<
    D0: rss_mdm_http_contract::module::Declaration,
    D1: rss_mdm_http_contract::module::Declaration,
    D2: rss_mdm_http_contract::module::Declaration,
>(
    authentication: Arc<AuthenticationState>,
    registry: Router<(), D0>,
    platform_settings: Router<(), D1>,
    diagnostics: Router<(), D2>,
    policy: Arc<Policy>,
    envelope: crate::boundary::Envelope,
    cursor: rss_mdm_query::cursor::CursorCodec,
    management_tenant: &str,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<D0, D1, D2>> {
    let routes = assemble(
        Some((&authentication, &policy, &envelope, &cursor)),
        Some(management_tenant),
        registry,
        platform_settings,
        diagnostics,
    );
    crate::boundary::wrap(routes, envelope)
}
pub fn contract_routes<
    D0: rss_mdm_http_contract::module::Declaration,
    D1: rss_mdm_http_contract::module::Declaration,
    D2: rss_mdm_http_contract::module::Declaration,
>(
    registry: Router<(), D0>,
    platform_settings: Router<(), D1>,
    diagnostics: Router<(), D2>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<D0, D1, D2>> {
    assemble(None, None, registry, platform_settings, diagnostics)
}
fn assemble<
    D0: rss_mdm_http_contract::module::Declaration,
    D1: rss_mdm_http_contract::module::Declaration,
    D2: rss_mdm_http_contract::module::Declaration,
>(
    runtime: Option<Runtime<'_>>,
    management_tenant: Option<&str>,
    registry: Router<(), D0>,
    platform_settings: Router<(), D1>,
    diagnostics: Router<(), D2>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<D0, D1, D2>> {
    let context = runtime.as_ref();
    let routes = {
        rss_mdm_http_contract::route_module! { struct AssembleModule2 for [Browser] { api_v1_tenant_administration at "/api/v1/tenant-administration" } }
        AssembleModule2 { api_v1_tenant_administration: {
 rss_mdm_http_contract::route_module! { struct AssembleModule101 for [Browser] { base, api_access_register_network, registry [optional], platform_settings, diagnostics } }
 AssembleModule101 { base: http::rule_routes()
            .bind_with(context, |(_, _, envelope, cursor)| {
                Arc::new(HttpState {
                    cursor: (*cursor).clone(),
                    audit_store: envelope.audit_store.clone(),
                })
            }),
api_access_register_network: crate::api_access::register_network().bind_with(
                context,
                |(authentication, _, envelope, cursor)| {
                    Arc::new(crate::api_access::Management {
                        cursor: (*cursor).clone(),
                        access: authentication.access.clone(),
                        audit: envelope.audit_store.clone(),
                    })
                },
            ),
registry,
platform_settings, diagnostics }.assemble()
} }.assemble()
    };
    let routes = http::mount_protection(
        routes,
        runtime.map(|(authentication, _, _, _)| authentication.clone()),
        true,
    );
    {
        rss_mdm_http_contract::route_module! { struct AssembleModule102 for [Browser] { base, router_mount_management_identity_context } }
        AssembleModule102 {
            base: routes,
            router_mount_management_identity_context:
                crate::router::mount_management_identity_context(
                    runtime.zip(management_tenant).map(
                        |((authentication, policy, _, _), tenant)| {
                            (authentication.clone(), policy.clone(), tenant)
                        },
                    ),
                ),
        }
        .assemble()
    }
}
