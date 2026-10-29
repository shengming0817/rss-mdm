use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};

use std::sync::Arc;
pub struct HttpState {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub devices: Arc<rss_mdm_registration_service::DeviceService>,
    pub assets: Arc<rss_mdm_inventory_service::assets::AssetService>,
    pub queries: Arc<rss_mdm_execution_service::queries::Queries>,
    pub windows: bool,
    pub apple: bool,
}
pub fn routes() -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_list, get_statistics, get_detail } }
        RoutesModule1 {
            get_list: rss_mdm_http_contract::module::Route::new(
                "/devices",
                get(list, &contracts::DEVICES, &[RouteOperation::List]),
            ),
            get_statistics: rss_mdm_http_contract::module::Route::new(
                "/devices/statistics",
                get(statistics, &contracts::DEVICES, &[RouteOperation::Query]),
            ),
            get_detail: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}",
                get(detail, &contracts::DEVICES, &[RouteOperation::Get]),
            ),
        }
        .assemble()
    }
}
async fn list(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<ListQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_registration_service::device::directory::Item,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "management_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let query = query.parse().map_err(|_| Error::Malformed)?;
        let assets = s.assets.clone();
        let page = s
            .devices
            .directory(&auth.proof, &query, &s.cursor, move |c, ids| {
                Box::pin(async move {
                    assets
                        .directory_presence_on(c, ids)
                        .await
                        .map_err(|_| rss_mdm_registration_service::Error::Storage)
                })
            })
            .await?;
        Ok(Json(page))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn statistics(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Statistics<DeviceStatisticsQuery>,
    >,
) -> Result<
    Json<
        rss_mdm_query::Statistics<
            rss_mdm_registration_service::device::directory::DeviceStatistics,
        >,
    >,
    Error,
> {
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let q = query.parse().map_err(|_| Error::Malformed)?;
    Ok(Json(s.devices.directory_statistics(&auth.proof, &q).await?))
}

async fn detail(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
) -> Result<Json<DeviceDetail>, Error> {
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target_device(&device);
    let devices = s.devices.clone();
    let assets = s.assets.clone();
    let selected = device.clone();
    let (item, capabilities) = s
        .queries
        .directory_device_snapshot(&auth.proof, &device, s.windows, s.apple, move |c| {
            Box::pin(async move {
                let mut item = devices.directory_device_on(c, &selected).await?;
                let present = assets
                    .directory_presence_on(c, std::slice::from_ref(&selected))
                    .await?;
                item.inventory_available = Some(present.contains(&selected));
                Ok(item)
            })
        })
        .await?;
    Ok(Json(DeviceDetail { item, capabilities }))
}

struct ListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ListQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_registration_service::device::directory::SCHEMA
    }
}

struct DeviceStatisticsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for DeviceStatisticsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_registration_service::device::directory::SCHEMA
    }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
struct DeviceDetail {
    #[serde(flatten)]
    item: rss_mdm_registration_service::device::directory::Item,
    capabilities: Vec<rss_mdm_execution_service::queries::records::Capability>,
}
