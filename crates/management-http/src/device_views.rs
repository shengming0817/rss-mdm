use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_device_service::{Associations, Confirm, Revoke, ViewQuery, ViewRef};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
pub fn routes() -> Router<Arc<Associations>> {
    Router::new()
        .route("/device-views", get(list))
        .route("/device-views/{kind}/{id}", get(detail))
        .route(
            "/device-views/{kind}/{id}/inventory-lists/{field}",
            get(items),
        )
        .route("/device-associations", post(confirm))
        .route("/device-associations/changes", get(changes))
        .route("/device-associations/{id}", get(association))
        .route("/device-associations/{id}/revoke", post(revoke))
        .route("/devices/{device}/association-candidates", get(candidates))
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
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: Result<Query<ViewQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>, Error> {
    audit.set_action("device_view_read");
    Ok(Json(
        s.views(&a.proof, &query.map_err(|_| Error::Malformed)?.0)
            .await?,
    ))
}
async fn detail(
    State(s): State<Arc<Associations>>,
    Extension(a): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((kind, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    audit.set_action("device_view_read");
    audit.target(&id);
    Ok(Json(s.view(&a.proof, &reference(kind, id)?).await?))
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
