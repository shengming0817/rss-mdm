//! Asset ownership reuses the registration relation and browser operation contract.
use super::http::HttpState;
use crate::{Error, api::write_key, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{Router, routing::get};
use rss_mdm_registration_service::device::registration_user::{
    RegistrationUser, RegistrationUserChange,
};
use std::sync::Arc;
type App = Arc<HttpState>;
pub fn routes() -> Router<App> {
    Router::new().route(
        "/devices/{device}/registration-user",
        get(responsibility)
            .owned(&contracts::DEVICES, &[RouteOperation::Action])
            .put(assign)
            .owned(
                &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Update],
            ),
    )
}
async fn responsibility(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Path(device): Path<String>,
) -> Result<Json<RegistrationUser>, Error> {
    app.devices
        .registration_user(&auth.proof, &device)
        .await
        .map(Json)
        .map_err(Into::into)
}
async fn assign(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    Path(device): Path<String>,
    input: Result<Json<RegistrationUserChange>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<RegistrationUser>, Error> {
    let key = write_key(&headers, &audit, "registration_user_change")?;
    let input = input.map_err(Error::from)?.0;
    app.devices
        .assign_registration_user(&auth.proof, &device, &input, key, &audit)
        .await
        .map(Json)
        .map_err(Into::into)
}
