use rss_mdm_http_contract::{
    Operation as RouteOperation, Router, catalog as contracts, routing::get,
};
pub fn routes(
    service: std::sync::Arc<rss_mdm_execution_service::ExecutionService>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register().with_state(service)
}
pub(crate) fn register() -> Router<
    std::sync::Arc<rss_mdm_execution_service::ExecutionService>,
    impl rss_mdm_http_contract::module::Declaration + use<>,
> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_download } }
        RegisterModule1 {
            get_download: rss_mdm_http_contract::module::Route::new(
                "/api/v1/software/installations/{id}/package",
                get(
                    download,
                    &contracts::DOWNLOAD_MANAGEMENT_HTTP,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    }
}
use crate::Error;
#[derive(schemars::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Download {
    token: String,
}
pub(crate) async fn download(
    axum::extract::State(service): axum::extract::State<
        std::sync::Arc<rss_mdm_execution_service::ExecutionService>,
    >,
    axum::Extension(audit): axum::Extension<rss_mdm_audit_integration::RequestAudit>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    axum::extract::Query(grant): axum::extract::Query<Download>,
    crate::content::http::DownloadHeaders(headers): crate::content::http::DownloadHeaders,
) -> Result<rss_mdm_http_contract::download::Download, Error> {
    crate::content::http::response(
        service
            .software_installation_content(id, &grant.token, &audit)
            .await?,
        &headers,
    )
    .await
}
