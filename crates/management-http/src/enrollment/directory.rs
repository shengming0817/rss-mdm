use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};

use serde::{Deserialize, Serialize};
use std::sync::Arc;
pub struct HttpState {
    pub cursor: rss_mdm_query::cursor::CursorCodec,
    pub devices: Arc<rss_mdm_registration_service::DeviceService>,
    pub reads: Arc<dyn DeviceReads>,
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
        let tenant = rss_request_context::TenantId::parse(auth.proof.tenant_id())
            .map_err(|_| Error::Unauthorized)?;
        let page = s
            .devices
            .directory(&auth, &query, &s.cursor, move |c, ids| {
                Box::pin(async move {
                    rss_mdm_inventory_service::assets::directory_presence_on(c, tenant, ids)
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
    Ok(Json(s.devices.directory_statistics(&auth, &q).await?))
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
    Ok(Json(s.reads.detail(&auth, &device).await?))
}

struct ListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ListQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution { rss_mdm_registration_service::device::directory::BINDINGS.execution() }
}

struct DeviceStatisticsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for DeviceStatisticsQuery {
    fn execution() -> &'static rss_mdm_query::directory::Execution { rss_mdm_registration_service::device::directory::BINDINGS.execution() }
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct DeviceDetail {
    #[serde(flatten)]
    pub item: rss_mdm_registration_service::device::directory::Item,
    pub capabilities: Vec<Capability>,
}

pub trait DeviceReads: Send + Sync {
    fn detail<'a>(
        &'a self,
        proof: &'a rss_mdm_authorization_service::context::RequestAuth,
        device: &'a str,
    ) -> crate::execution::task_reads::Pending<'a, DeviceDetail>;
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportState {
    Supported,
    Unsupported,
    Blocked,
    Unknown,
    Ready,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReason {
    ProductNotConfigured,
    NotRegistered,
    CapabilityUnknown,
    CapabilityNotSupported,
    PermissionDenied,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
pub struct Support {
    pub state: SupportState,
    pub reason: Option<CapabilityReason>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
pub struct Permission {
    pub allowed: bool,
    pub reason: Option<CapabilityReason>,
}
#[derive(schemars::JsonSchema, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub action: String,
    pub channel: String,
    pub product_support: Support,
    pub device_prerequisite: Support,
    pub permission: Permission,
}
