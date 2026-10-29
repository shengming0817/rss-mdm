//! SMTP 仅发布材料和固定资格投递请求；普通 HTTP 不执行宿主或网络维护。
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
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
pub fn routes(
    authority: Arc<Authority>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register(Some(cursor)).with_state(authority)
}
pub(crate) fn register(
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<Authority>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    let router = {
 rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_history, get_read, post_create, get_operation } }
 RegisterModule1 { get_history: rss_mdm_http_contract::module::Route::new("/smtp/versions", get(history, &contracts::SMTP_VERSIONS, &[RouteOperation::List])),
get_read: rss_mdm_http_contract::module::Route::new("/smtp", rss_mdm_http_contract::routing::get(read, &contracts::SMTP, &[RouteOperation::Get])),
post_create: rss_mdm_http_contract::module::Route::new("/smtp", rss_mdm_http_contract::routing::post(create, &contracts::SMTP, &[RouteOperation::Update])),
get_operation: rss_mdm_http_contract::module::Route::new("/smtp/operations/{id}", get(operation, &contracts::SMTP, &[RouteOperation::Get])) }.assemble()
}
        .layer(axum::extract::DefaultBodyLimit::max(16384));
    match cursor {
        Some(cursor) => router.layer(Extension(cursor)),
        None => router,
    }
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
    headers: crate::api::WriteHeaders,
    input: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Result<rss_mdm_http_contract::signature::WithStatus<202, Json<Receipt>>, Error> {
    let id = crate::api::write_key(&headers, &audit, "smtp_qualification")?;
    let input = input.map_err(Error::from)?.0;
    Ok(rss_mdm_http_contract::signature::WithStatus(Json(
        service.create(&auth.proof, &audit, id, &input).await?,
    )))
}

async fn history(
    State(service): State<Arc<Authority>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(cursor): Extension<rss_mdm_query::cursor::CursorCodec>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Window<HistoryQuery>,
    >,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<rss_mdm_query::Page<Receipt>>>, Error> {
    (async {
        let (q, _) = query.parse().map_err(|_| Error::Malformed)?;
        service
            .history(&auth.proof, &audit, &q, &cursor)
            .await
            .map(Json)
            .map_err(Error::from)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

struct HistoryQuery;
impl rss_mdm_http_contract::query::WindowOwner for HistoryQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_mail_service::authority::HISTORY
    }
}
