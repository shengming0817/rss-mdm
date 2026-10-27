use rss_mdm_http_contract::{
    Operation as RouteOperation, Router, catalog as contracts, routing::get,
};
pub fn routes(service: std::sync::Arc<rss_mdm_execution_service::ExecutionService>) -> Router {
    register().with_state(service)
}
pub(crate) fn register() -> Router<std::sync::Arc<rss_mdm_execution_service::ExecutionService>> {
    Router::new().route(
        "/api/v1/software/installations/{id}/package",
        get(download).owned(
            &contracts::DOWNLOAD_MANAGEMENT_HTTP,
            &[RouteOperation::Action],
        ),
    )
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
