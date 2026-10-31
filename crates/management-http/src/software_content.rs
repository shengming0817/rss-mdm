use rss_mdm_http_contract::{
    Operation as RouteOperation, Router, catalog as contracts, routing::get,
};
pub fn routes(
    service: std::sync::Arc<dyn Packages>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register().with_state(service)
}
pub(crate) fn register()
-> Router<std::sync::Arc<dyn Packages>, impl rss_mdm_http_contract::module::Declaration + use<>> {
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
    axum::extract::State(service): axum::extract::State<std::sync::Arc<dyn Packages>>,
    axum::Extension(audit): axum::Extension<rss_mdm_audit_integration::RequestAudit>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    axum::extract::Query(grant): axum::extract::Query<Download>,
    crate::content::http::DownloadHeaders(headers): crate::content::http::DownloadHeaders,
) -> Result<rss_mdm_http_contract::download::Download, Error> {
    crate::content::http::response(service.download(id, &grant.token, &audit).await?, &headers)
        .await
}

/// App composes exact Software authorization with Content byte verification.
pub trait Packages: Send + Sync {
    fn download<'a>(
        &'a self,
        id: uuid::Uuid,
        token: &'a str,
        audit: &'a rss_mdm_audit_integration::RequestAudit,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<rss_mdm_content_service::Verified, crate::Error>>
                + Send
                + 'a,
        >,
    >;
}
