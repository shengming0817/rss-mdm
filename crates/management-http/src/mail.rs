//! SMTP 仅发布材料和固定资格投递请求；普通 HTTP 不执行宿主或网络维护。
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_mail_service::{
    authority::Authority,
    store::{Directory, Receipt, Request},
};
use std::sync::Arc;
use uuid::Uuid;
pub fn routes(authority: Arc<Authority>) -> Router {
    Router::new()
        .route(
            "/smtp",
            get(read)
                .owned(&contracts::SMTP, &[RouteOperation::Get])
                .post(create)
                .owned(&contracts::SMTP, &[RouteOperation::Update]),
        )
        .route(
            "/smtp/operations/{id}",
            get(operation).owned(&contracts::SMTP, &[RouteOperation::Get]),
        )
        .layer(axum::extract::DefaultBodyLimit::max(16384))
        .with_state(authority)
}
async fn read(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> Result<Json<Directory>, Error> {
    audit.set_action("smtp_read", rss_mdm_audit_integration::AuditIntent::Routine);
    Ok(Json(service.read(&auth.proof, &audit).await?))
}
async fn operation(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Receipt>, Error> {
    audit.set_action("smtp_read", rss_mdm_audit_integration::AuditIntent::Routine);
    Ok(Json(service.operation(&auth.proof, &audit, id).await?))
}
async fn create(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    input: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Receipt>), Error> {
    let id = crate::api::write_key(&headers, &audit, "smtp_qualification")?;
    let input = input.map_err(Error::from)?.0;
    Ok((
        StatusCode::ACCEPTED,
        Json(service.create(&auth.proof, &audit, id, &input).await?),
    ))
}
