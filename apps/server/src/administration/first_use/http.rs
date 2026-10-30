//! Authenticated tenant setup intent. Configuration and observations retain their domain owners.
use super::{FirstUse, model::*};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::RequestAuth;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_management_http::{Error, http_operation::RequestContinuation};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) fn register()
-> Router<Arc<FirstUse>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
 rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_read, put_update, get_operation } }
 RegisterModule1 { get_read: rss_mdm_http_contract::module::Route::new("/settings/first-use", rss_mdm_http_contract::routing::get(read, &contracts::FIRST_USE, &[RouteOperation::Get])),
put_update: rss_mdm_http_contract::module::Route::new("/settings/first-use", rss_mdm_http_contract::routing::put(update, &contracts::FIRST_USE, &[RouteOperation::Update])),
get_operation: rss_mdm_http_contract::module::Route::new("/settings/first-use/operations/{id}", get(operation, &contracts::FIRST_USE, &[RouteOperation::Get])) }.assemble()
}
        .layer(axum::extract::DefaultBodyLimit::max(16384))
}
async fn read(
    State(source): State<Arc<FirstUse>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<RequestContinuation>,
) -> Result<Json<Progress>, Error> {
    audit.set_action(
        "first_use_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    source
        .read(&auth, &audit, continuation.secret())
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn operation(
    State(source): State<Arc<FirstUse>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> Result<Json<Receipt>, Error> {
    audit.set_action(
        "first_use_operation_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    source
        .operation(&auth.proof, &audit, id)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn update(
    State(source): State<Arc<FirstUse>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(continuation): Extension<RequestContinuation>,
    headers: rss_mdm_management_http::api::WriteHeaders,
    input: Result<Json<Update>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Receipt>, Error> {
    let id = rss_mdm_management_http::api::write_key(&headers, &audit, "first_use_update")?;
    source
        .update(&auth, &audit, continuation.secret(), id, input?.0)
        .await
        .map(Json)
        .map_err(Error::from)
}
