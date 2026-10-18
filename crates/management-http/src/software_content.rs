use crate::Error;
#[derive(serde::Deserialize)]
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
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, Error> {
    crate::content::http::response(
        service
            .software_installation_content(id, &grant.token, &audit)
            .await?,
        &headers,
    )
    .await
}
