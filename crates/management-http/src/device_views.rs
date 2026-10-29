use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_device_service::{Associations, Confirm, Revoke, ViewRef};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
pub fn routes(
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    identity: rss_identity_postgres::Authority,
    platform: Option<rss_mdm_device_service::personnel::PlatformConfiguration>,
) -> Router<Arc<Associations>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    register(Some((sessions, identity, platform)))
}
pub(crate) fn register(
    runtime: Option<(
        Arc<rss_mdm_authorization_service::session::SessionAuthority>,
        rss_identity_postgres::Authority,
        Option<rss_mdm_device_service::personnel::PlatformConfiguration>,
    )>,
) -> Router<Arc<Associations>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_list, get_statistics, get_retirement, post_force_retirement, post_asset_state, get_detail, get_items, post_confirm, get_association_list, get_changes, get_association, post_revoke, get_candidates } }
        RegisterModule1 {
            get_list: rss_mdm_http_contract::module::Route::new(
                "/device-views",
                get(list, &contracts::DEVICE_VIEWS, &[RouteOperation::List]),
            ),
            get_statistics: rss_mdm_http_contract::module::Route::new(
                "/device-views/statistics",
                get(
                    statistics,
                    &contracts::DEVICE_VIEWS,
                    &[RouteOperation::Query],
                ),
            ),
            get_retirement: rss_mdm_http_contract::module::Route::new(
                "/device-retirements/{id}",
                get(
                    retirement,
                    &contracts::DEVICE_RETIREMENTS,
                    &[RouteOperation::Get],
                ),
            ),
            post_force_retirement: rss_mdm_http_contract::module::Route::new(
                "/device-retirements/{id}/force-revoke",
                post(
                    force_retirement,
                    &contracts::DEVICE_RETIREMENTS,
                    &[RouteOperation::Action, RouteOperation::Lifecycle],
                ),
            ),
            post_asset_state: rss_mdm_http_contract::module::Route::new(
                "/device-views/{kind}/{id}/asset-state",
                post(
                    asset_state,
                    &contracts::DEVICE_VIEWS,
                    &[RouteOperation::Action, RouteOperation::Update],
                ),
            ),
            get_detail: rss_mdm_http_contract::module::Route::new(
                "/device-views/{kind}/{id}",
                get(detail, &contracts::DEVICE_VIEWS, &[RouteOperation::Get]),
            ),
            get_items: rss_mdm_http_contract::module::Route::new(
                "/device-views/{kind}/{id}/inventory-lists/{field}",
                get(
                    items,
                    &contracts::DEVICE_VIEW_ITEMS,
                    &[RouteOperation::List],
                ),
            ),
            post_confirm: rss_mdm_http_contract::module::Route::new(
                "/device-associations",
                rss_mdm_http_contract::routing::post(
                    confirm,
                    &contracts::DEVICE_ASSOCIATIONS,
                    &[RouteOperation::Create],
                ),
            ),
            get_association_list: rss_mdm_http_contract::module::Route::new(
                "/device-associations",
                rss_mdm_http_contract::routing::get(
                    association_list,
                    &contracts::DEVICE_ASSOCIATIONS,
                    &[RouteOperation::List],
                ),
            ),
            get_changes: rss_mdm_http_contract::module::Route::new(
                "/device-associations/changes",
                get(
                    changes,
                    &contracts::ASSOCIATION_CHANGES,
                    &[RouteOperation::List],
                ),
            ),
            get_association: rss_mdm_http_contract::module::Route::new(
                "/device-associations/{id}",
                get(
                    association,
                    &contracts::DEVICE_ASSOCIATIONS,
                    &[RouteOperation::Get],
                ),
            ),
            post_revoke: rss_mdm_http_contract::module::Route::new(
                "/device-associations/{id}/revoke",
                post(
                    revoke,
                    &contracts::DEVICE_ASSOCIATIONS,
                    &[RouteOperation::Lifecycle],
                ),
            ),
            get_candidates: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/association-candidates",
                get(
                    candidates,
                    &contracts::DEVICE_ASSOCIATION_CANDIDATES,
                    &[RouteOperation::List],
                ),
            ),
        }
        .assemble()
    };
    match runtime {
        Some((sessions, identity, platform)) => router
            .layer(Extension(sessions))
            .layer(Extension(identity))
            .layer(Extension(platform)),
        None => router,
    }
}
fn reference(kind: String, id: String) -> Result<ViewRef, Error> {
    match kind.as_str() {
        "endpoint" => Ok(ViewRef::Endpoint(id)),
        "association" => Ok(ViewRef::Association(
            Uuid::parse_str(&id).map_err(|_| Error::Malformed)?,
        )),
        _ => Err(Error::Malformed),
    }
}
async fn list(
    State(s): State<Arc<Associations>>,
    (Extension(identity), Extension(deadline)): (
        Extension<rss_identity_postgres::Authority>,
        Extension<crate::runtime_diagnostics::RequestDeadline>,
    ),
    Extension(platform): Extension<
        Option<rss_mdm_device_service::personnel::PlatformConfiguration>,
    >,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<DeviceDirectoryQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_device_service::view_response::Directory>,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "device_view_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        Ok(Json(
            s.views(
                &a.proof,
                &query.parse().map_err(|_| Error::Malformed)?,
                &rss_mdm_device_service::personnel::Reader::new(
                    &identity,
                    deadline.0,
                    &rss_mdm_audit_integration::budget::RuntimeTimer,
                    platform.as_ref(),
                ),
            )
            .await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn statistics(
    State(s): State<Arc<Associations>>,
    (Extension(identity), Extension(deadline)): (
        Extension<rss_identity_postgres::Authority>,
        Extension<crate::runtime_diagnostics::RequestDeadline>,
    ),
    Extension(platform): Extension<
        Option<rss_mdm_device_service::personnel::PlatformConfiguration>,
    >,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Statistics<DeviceStatisticsQuery>,
    >,
) -> Result<Json<rss_mdm_device_service::view_response::StatisticsResponse>, Error> {
    audit.set_action(
        "device_view_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let mut query = query.parse().map_err(|_| Error::Malformed)?;
    query
        .default_filter("assetState", "active")
        .map_err(|_| Error::Malformed)?;
    Ok(Json(
        s.statistics(
            &a.proof,
            &query,
            &rss_mdm_device_service::personnel::Reader::new(
                &identity,
                deadline.0,
                &rss_mdm_audit_integration::budget::RuntimeTimer,
                platform.as_ref(),
            ),
        )
        .await?,
    ))
}
async fn detail(
    State(s): State<Arc<Associations>>,
    (Extension(identity), Extension(deadline)): (
        Extension<rss_identity_postgres::Authority>,
        Extension<crate::runtime_diagnostics::RequestDeadline>,
    ),
    Extension(platform): Extension<
        Option<rss_mdm_device_service::personnel::PlatformConfiguration>,
    >,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((kind, id)): Path<(String, String)>,
) -> Result<Json<rss_mdm_device_service::view_response::Detail>, Error> {
    audit.set_action(
        "device_view_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let reference = reference(kind, id)?;
    match &reference {
        ViewRef::Endpoint(id) => audit.target_device(id),
        ViewRef::Association(id) => audit.target(&id.to_string()),
    }
    Ok(Json(
        s.view(
            &a.proof,
            &reference,
            &rss_mdm_device_service::personnel::Reader::new(
                &identity,
                deadline.0,
                &rss_mdm_audit_integration::budget::RuntimeTimer,
                platform.as_ref(),
            ),
        )
        .await?,
    ))
}
async fn items(
    State(s): State<Arc<Associations>>,
    (Extension(identity), Extension(deadline)): (
        Extension<rss_identity_postgres::Authority>,
        Extension<crate::runtime_diagnostics::RequestDeadline>,
    ),
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((kind, id, field)): Path<(String, String, String)>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<ItemsQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_device_service::view_response::ListItems>,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "device_view_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let (q, _) = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(
            s.list_items(
                &a.proof,
                &reference(kind, id)?,
                rss_mdm_inventory::FieldKey::parse(&field).map_err(|_| Error::Malformed)?,
                q.cursor().as_deref().ok_or(Error::Malformed)?,
                q.limit(),
                &rss_mdm_device_service::personnel::Reader::new(
                    &identity,
                    deadline.0,
                    &rss_mdm_audit_integration::budget::RuntimeTimer,
                    None,
                ),
            )
            .await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn association(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_device_service::Association>, Error> {
    audit.set_action(
        "device_association_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(s.get(&a.proof, id).await?))
}
async fn confirm(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<Confirm>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<rss_mdm_device_service::Association>, Error> {
    audit.set_action(
        "device_association_confirm",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    Ok(Json(
        s.confirm(&a.proof, &body.map_err(Error::from)?.0, &audit)
            .await?,
    ))
}
async fn revoke(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<Json<Revoke>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<rss_mdm_device_service::Association>, Error> {
    audit.set_action(
        "device_association_revoke",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    Ok(Json(
        s.revoke(&a.proof, id, &body.map_err(Error::from)?.0, &audit)
            .await?,
    ))
}
async fn candidates(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<CandidatesQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<Json<rss_mdm_device_service::CandidatePage>>,
    Error,
> {
    (async {
        audit.set_action(
            "device_association_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let (q, context) = query.parse().map_err(|_| Error::Malformed)?;
        let channel = serde_json::from_value(Value::String(
            context.get("channel").ok_or(Error::Malformed)?.clone(),
        ))
        .map_err(|_| Error::Malformed)?;
        Ok(Json(
            s.candidates(&a.proof, &device, channel, q.cursor().as_deref(), q.limit())
                .await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn changes(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<ChangesQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<rss_mdm_query::Page<rss_mdm_device_service::changes::ChangeEntry>>,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "device_association_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        Ok(Json(
            s.changes(&a.proof, &query.parse().map_err(|_| Error::Malformed)?.0)
                .await?,
        ))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn retirement(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_device_service::lifecycle::Retirement>, Error> {
    audit.set_action(
        "device_retirement_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    Ok(Json(s.retirement(&a.proof, id).await?))
}
async fn force_retirement(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
    body: Result<
        Json<rss_mdm_device_service::lifecycle_management::ForceRevoke>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_device_service::lifecycle_management::ForceReceipt>, Error> {
    Ok(Json(
        s.force_retirement(&a.proof, id, &body.map_err(Error::from)?.0, &audit)
            .await?,
    ))
}
async fn asset_state(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((kind, id)): Path<(String, String)>,
    body: Result<
        Json<rss_mdm_device_service::lifecycle_management::AssetChange>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<rss_mdm_device_service::lifecycle_management::AssetReceipt>, Error> {
    Ok(Json(
        s.asset_state(
            &a.proof,
            &reference(kind, id)?,
            &body.map_err(Error::from)?.0,
            &audit,
        )
        .await?,
    ))
}

async fn association_list(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<AssociationListQuery>,
    >,
) -> Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_query::Page<
                rss_mdm_query::directory::Projection<
                    rss_mdm_device_service::association_directory::AssociationRow,
                >,
            >,
        >,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "device_association_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(s.directory(&a.proof, &q).await?))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

struct ItemsQuery;
impl rss_mdm_http_contract::query::WindowOwner for ItemsQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_device_service::association_directory::SOURCE_ITEMS
    }
}

struct CandidatesQuery;
impl rss_mdm_http_contract::query::WindowOwner for CandidatesQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_device_service::association_directory::CANDIDATES
    }
}

struct ChangesQuery;
impl rss_mdm_http_contract::query::WindowOwner for ChangesQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_device_service::changes::SCHEMA
    }
}

struct AssociationListQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for AssociationListQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_device_service::association_directory::SCHEMA
    }
}

struct DeviceDirectoryQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for DeviceDirectoryQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_device_service::directory::SCHEMA
    }
    fn parse(raw: &str) -> rss_mdm_query::Result<rss_mdm_query::directory::Query> {
        rss_mdm_device_service::directory::parse(raw)
    }
}

struct DeviceStatisticsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for DeviceStatisticsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_device_service::directory::SCHEMA
    }
}
