use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use serde_json::Value;
use std::sync::Arc;
pub struct HttpState {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub devices: Arc<rss_mdm_registration_service::DeviceService>,
    pub assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub windows: bool,
    pub apple: bool,
}
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/devices",
            get(list)
                .owned(&contracts::DEVICES, &[RouteOperation::List])
                .queried(&rss_mdm_registration_service::device::directory::SCHEMA),
        )
        .route(
            "/devices/statistics",
            get(statistics).owned(&contracts::DEVICES, &[RouteOperation::Query]),
        )
        .route(
            "/devices/{device}",
            get(detail).owned(&contracts::DEVICES, &[RouteOperation::Get]),
        )
}
async fn list(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    RawQuery(raw): RawQuery,
) -> Result<Json<Value>, Error> {
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let query = rss_mdm_registration_service::device::directory::SCHEMA
        .parse(raw.as_deref().unwrap_or(""))
        .map_err(|_| Error::Malformed)?;
    let mut page = s.devices.directory(&auth.proof, &query, &s.cursor).await?;
    if query.selects("inventoryAvailable") {
        let ids = page
            .items
            .iter()
            .map(|v| v["id"].as_str().map(str::to_owned).ok_or(Error::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        let present = s
            .assets
            .directory_presence(&auth.proof, &ids, &audit)
            .await?;
        for item in &mut page.items {
            item["inventoryAvailable"] =
                Value::Bool(present.contains(item["id"].as_str().ok_or(Error::Malformed)?));
        }
    }
    let page = s
        .devices
        .finish_directory(&auth.proof, &query, page)
        .await?;
    Ok(Json(
        serde_json::to_value(page).map_err(|_| Error::Malformed)?,
    ))
}
async fn statistics(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    RawQuery(raw): RawQuery,
) -> Result<Json<Value>, Error> {
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let q = rss_mdm_registration_service::device::directory::SCHEMA
        .statistics(raw.as_deref().unwrap_or(""))
        .map_err(|_| Error::Malformed)?;
    Ok(Json(s.devices.directory_statistics(&auth.proof, &q).await?))
}

async fn detail(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
) -> Result<Json<Value>, Error> {
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target_device(&device);
    let mut item = s.devices.directory_device(&auth.proof, &device).await?;
    let present = s
        .assets
        .directory_presence(&auth.proof, std::slice::from_ref(&device), &audit)
        .await?;
    item["inventoryAvailable"] = Value::Bool(present.contains(&device));
    item["capabilities"] = serde_json::to_value(
        s.queries
            .directory_capabilities(&auth.proof, &device, s.windows, s.apple)
            .await?,
    )
    .expect("capability facts serialize");
    Ok(Json(item))
}
