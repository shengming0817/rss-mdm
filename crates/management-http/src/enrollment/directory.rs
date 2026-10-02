use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use rss_mdm_audit_integration::RequestAudit;
use serde_json::Value;
use std::sync::Arc;
pub struct HttpState {
    pub devices: Arc<rss_mdm_registration_service::DeviceService>,
    pub assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub execution: Arc<rss_mdm_execution_service::ExecutionService>,
    pub windows: bool,
    pub apple: bool,
}
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/devices", get(list))
        .route("/devices/{device}", get(detail))
}
async fn list(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: Result<
        Query<rss_mdm_registration_service::device::directory::Query>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    let Query(query) = query.map_err(|_| Error(rss_mdm_flow_service::Error::Malformed))?;
    let mut page = s.devices.directory(&auth.proof, &query).await?;
    let ids = page["items"]
        .as_array()
        .ok_or(Error(rss_mdm_flow_service::Error::Malformed))?
        .iter()
        .filter_map(|v| v["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    let present = s
        .assets
        .directory_presence(&auth.proof, &ids, &audit)
        .await?;
    for item in page["items"]
        .as_array_mut()
        .ok_or(Error(rss_mdm_flow_service::Error::Malformed))?
    {
        item["inventoryAvailable"] =
            Value::Bool(present.contains(item["id"].as_str().unwrap_or_default()));
    }
    Ok(Json(page))
}
async fn detail(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
) -> Result<Json<Value>, Error> {
    audit.set_action("management_read");
    audit.target(&device);
    let mut item = s.devices.directory_device(&auth.proof, &device).await?;
    let present = s
        .assets
        .directory_presence(&auth.proof, std::slice::from_ref(&device), &audit)
        .await?;
    item["inventoryAvailable"] = Value::Bool(present.contains(&device));
    item["capabilities"] = s
        .execution
        .directory_capabilities(&auth.proof, &device, &item["channels"], s.windows, s.apple)
        .await?;
    Ok(Json(item))
}
