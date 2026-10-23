use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_device_service::{Associations, Confirm, Revoke, ViewQuery, ViewRef};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
pub fn routes(
    sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    identity: rss_identity_postgres::Authority,
    platform: Option<rss_mdm_device_service::personnel::PlatformConfiguration>,
) -> Router<Arc<Associations>> {
    Router::new()
        .route(
            "/device-views",
            get(list).owned(&contracts::DEVICE_VIEWS, &[RouteOperation::List]),
        )
        .route(
            "/device-retirements/{id}",
            get(retirement).owned(&contracts::DEVICE_RETIREMENTS, &[RouteOperation::Get]),
        )
        .route(
            "/device-retirements/{id}/force-revoke",
            post(force_retirement).owned(&contracts::DEVICE_RETIREMENTS, &[RouteOperation::Action]),
        )
        .route(
            "/device-views/{kind}/{id}/asset-state",
            post(asset_state).owned(&contracts::DEVICE_VIEWS, &[RouteOperation::Action]),
        )
        .route(
            "/device-views/{kind}/{id}",
            get(detail).owned(&contracts::DEVICE_VIEWS, &[RouteOperation::Get]),
        )
        .route(
            "/device-views/{kind}/{id}/inventory-lists/{field}",
            get(items).owned(&contracts::DEVICE_VIEWS, &[RouteOperation::Action]),
        )
        .route(
            "/device-associations",
            post(confirm).owned(&contracts::DEVICE_ASSOCIATIONS, &[RouteOperation::Create]),
        )
        .route(
            "/device-associations/changes",
            get(changes).owned(&contracts::DEVICE_ASSOCIATIONS, &[RouteOperation::List]),
        )
        .route(
            "/device-associations/{id}",
            get(association).owned(&contracts::DEVICE_ASSOCIATIONS, &[RouteOperation::Get]),
        )
        .route(
            "/device-associations/{id}/revoke",
            post(revoke).owned(
                &contracts::DEVICE_ASSOCIATIONS,
                &[RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/devices/{device}/association-candidates",
            get(candidates).owned(&contracts::DEVICES, &[RouteOperation::Action]),
        )
        .layer(Extension(sessions))
        .layer(Extension(identity))
        .layer(Extension(platform))
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
    query: Result<Query<ViewQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>, Error> {
    audit.set_action("device_view_read");
    Ok(Json(
        s.views(
            &a.proof,
            &query.map_err(|_| Error::Malformed)?.0,
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
) -> Result<Json<Value>, Error> {
    audit.set_action("device_view_read");
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Items {
    cursor: String,
    #[serde(default = "limit")]
    limit: usize,
}
fn limit() -> usize {
    64
}
async fn items(
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
    Path((kind, id, field)): Path<(String, String, String)>,
    query: Result<Query<Items>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>, Error> {
    audit.set_action("device_view_read");
    let q = query.map_err(|_| Error::Malformed)?.0;
    Ok(Json(
        s.list_items(
            &a.proof,
            &reference(kind, id)?,
            rss_mdm_inventory::FieldKey::parse(&field).map_err(|_| Error::Malformed)?,
            &q.cursor,
            q.limit,
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
async fn association(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_device_service::Association>, Error> {
    audit.set_action("device_association_read");
    Ok(Json(s.get(&a.proof, id).await?))
}
async fn confirm(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    body: Result<Json<Confirm>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<rss_mdm_device_service::Association>, Error> {
    audit.set_action("device_association_confirm");
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
    audit.set_action("device_association_revoke");
    Ok(Json(
        s.revoke(&a.proof, id, &body.map_err(Error::from)?.0, &audit)
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidates {
    channel: rss_mdm_inventory::Channel,
    after: Option<String>,
    #[serde(default = "limit")]
    limit: usize,
}
async fn candidates(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    query: Result<Query<Candidates>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<rss_mdm_device_service::CandidatePage>, Error> {
    audit.set_action("device_association_read");
    let q = query.map_err(|_| Error::Malformed)?.0;
    Ok(Json(
        s.candidates(&a.proof, &device, q.channel, q.after.as_deref(), q.limit)
            .await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Changes {
    cursor: Option<String>,
}
async fn changes(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: Result<Query<Changes>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>, Error> {
    audit.set_action("device_association_read");
    Ok(Json(
        s.changes(
            &a.proof,
            query.map_err(|_| Error::Malformed)?.0.cursor.as_deref(),
        )
        .await?,
    ))
}

async fn retirement(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<rss_mdm_device_service::lifecycle::Retirement>, Error> {
    audit.set_action("device_retirement_read");
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
) -> Result<Json<Value>, Error> {
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
) -> Result<Json<Value>, Error> {
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
