use super::{Directory, model::*};
use axum::{Extension, Json};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::RequestAuth;
use rss_mdm_management_http::{Error, http_operation::RequestContinuation};
use std::sync::Arc;
async fn directory(
    source: Arc<Directory>,
    auth: RequestAuth,
    audit: RequestAudit,
    continuation: RequestContinuation,
    platform: bool,
) -> Result<Json<Catalog>, Error> {
    let items = catalog(&auth.proof, platform).map_err(Error::from)?;
    let expected = items.iter().map(|i| i.id).collect::<Vec<_>>();
    let entries = source
        .project(auth.proof.clone(), audit, continuation.secret(), items)
        .await
        .map_err(Error::from)?;
    if entries.iter().map(|e| e.item.id).collect::<Vec<_>>() != expected {
        return Err(Error::Conflict);
    }
    auth.proof.check_live()?;
    Ok(Json(Catalog {
        items: entries,
        domains: domains(&auth.proof, platform),
    }))
}
pub(crate) fn register() -> rss_mdm_http_contract::Router<
    Arc<Directory>,
    impl rss_mdm_http_contract::module::Declaration + use<>,
> {
    use rss_mdm_http_contract::{Operation, catalog, routing::get};
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_tenant } }
        RegisterModule1 {
            get_tenant: rss_mdm_http_contract::module::Route::new(
                "/settings/catalog",
                get(tenant, &catalog::SETTINGS_CATALOG, &[Operation::Get]),
            ),
        }
        .assemble()
    }
}
pub(crate) async fn tenant(
    axum::extract::State(source): axum::extract::State<Arc<Directory>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<RequestContinuation>,
) -> Result<Json<Catalog>, Error> {
    directory(source, auth, audit, continuation, false).await
}
pub(crate) async fn platform(
    axum::extract::State(source): axum::extract::State<Arc<Directory>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<RequestContinuation>,
) -> Result<Json<Catalog>, Error> {
    directory(source, auth, audit, continuation, true).await
}

pub(crate) fn platform_routes(
    runtime: Option<&Arc<Directory>>,
) -> rss_mdm_http_contract::Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    use rss_mdm_http_contract::{Operation, catalog, routing::get};
    rss_mdm_http_contract::route_module! { struct PlatformSettings for [Browser] { catalog } }
    PlatformSettings {
        catalog: rss_mdm_http_contract::module::Route::new(
            "/settings/catalog",
            get(platform, &catalog::SETTINGS_CATALOG, &[Operation::Get]),
        ),
    }
    .assemble()
    .bind_with(runtime, Clone::clone)
}
