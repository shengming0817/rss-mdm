//! Administrator reads reuse the existing request proof and response boundary.
//! ref: axum axum/src/extract/query.rs@axum-v0.8.9
use crate::{Error, Failure, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_timeline_service::{Page, Timeline};
use std::sync::Arc;
fn input(
    q: Result<Query<rss_mdm_timeline_service::Query>, axum::extract::rejection::QueryRejection>,
) -> Result<rss_mdm_timeline_service::Query, Error> {
    q.map(|q| q.0).map_err(|_| Error::Malformed)
}
fn error(error: rss_mdm_timeline_service::Error) -> Error {
    use rss_mdm_timeline_service::Error as E;
    match error {
        E::Malformed => Error::Malformed,
        E::Conflict => Error::Conflict,
        E::Forbidden => Error::Forbidden,
        E::Integrity => Error::Unavailable(Failure::AuditIntegrity),
        E::Storage | E::Deadline => Error::Unavailable(Failure::Timeline),
    }
}
pub fn routes() -> Router<Arc<Timeline>> {
    Router::new()
        .route(
            "/devices/{device}/timeline",
            get(device).owned(&contracts::DEVICE_TIMELINE, &[RouteOperation::List]),
        )
        .route(
            "/audit-events",
            get(search).owned(&contracts::AUDIT, &[RouteOperation::List]),
        )
}
async fn device(
    State(service): State<Arc<Timeline>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    params: Result<
        Query<rss_mdm_timeline_service::Query>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Page>, Error> {
    audit.target_device(&device);
    let mut query = input(params)?;
    if query.device.is_some() {
        return Err(Error::Malformed);
    }
    query.device = Some(device);
    service
        .query(&auth.proof, "device", &query)
        .await
        .map(Json)
        .map_err(error)
}
async fn search(
    State(service): State<Arc<Timeline>>,
    Extension(auth): Extension<RequestAuth>,
    params: Result<
        Query<rss_mdm_timeline_service::Query>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<Page>, Error> {
    service
        .query(&auth.proof, "audit", &input(params)?)
        .await
        .map(Json)
        .map_err(error)
}
