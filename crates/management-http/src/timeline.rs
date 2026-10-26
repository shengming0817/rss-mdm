//! Administrator reads reuse the existing request proof and response boundary.
//! ref: axum axum/src/extract/query.rs@axum-v0.8.9
use crate::{Error, Failure, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_timeline_service::{Page, Timeline};
use std::sync::Arc;
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
            get(device)
                .owned(&contracts::DEVICE_TIMELINE, &[RouteOperation::List])
                .windowed(&rss_mdm_timeline_service::DEVICE_TIMELINE),
        )
        .route(
            "/audit-events",
            get(search)
                .owned(&contracts::AUDIT, &[RouteOperation::List])
                .windowed(&rss_mdm_timeline_service::AUDIT),
        )
}
async fn device(
    State(service): State<Arc<Timeline>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    RawQuery(params): RawQuery,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Page>>, Error> {
    (async {
        audit.target_device(&device);
        let mut query =
            rss_mdm_timeline_service::Query::parse(params.as_deref().unwrap_or(""), true)
                .map_err(error)?;
        if query.device.is_some() {
            return Err(Error::Malformed);
        }
        query.device = Some(device);
        service
            .query(&auth.proof, "device", &query)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn search(
    State(service): State<Arc<Timeline>>,
    Extension(audit): Extension<RequestAudit>,
    Extension(auth): Extension<RequestAuth>,
    RawQuery(params): RawQuery,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Page>>, Error> {
    (async {
        audit.intent(rss_mdm_audit_integration::AuditIntent::Sensitive(
            rss_mdm_audit_integration::SensitiveAction::AuditHistoryRead,
        ));
        service
            .query(
                &auth.proof,
                "audit",
                &rss_mdm_timeline_service::Query::parse(params.as_deref().unwrap_or(""), false)
                    .map_err(error)?,
            )
            .await
            .map(Json)
            .map_err(error)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
