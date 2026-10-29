//! Asset ownership reuses the registration relation and browser operation contract.
use super::http::HttpState;
use crate::{Error, api::write_key, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::Router;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_registration_service::device::registration_user::{
    RegistrationUser, RegistrationUserChange,
};
use std::sync::Arc;
type App = Arc<HttpState>;
pub fn routes() -> Router<App, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Browser] { get_responsibility, put_assign } }
        RoutesModule1 {
            get_responsibility: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/registration-user",
                rss_mdm_http_contract::routing::get(
                    responsibility,
                    &contracts::DEVICES,
                    &[RouteOperation::Action],
                ),
            ),
            put_assign: rss_mdm_http_contract::module::Route::new(
                "/devices/{device}/registration-user",
                rss_mdm_http_contract::routing::put(
                    assign,
                    &contracts::DEVICES,
                    &[RouteOperation::Action, RouteOperation::Update],
                ),
            ),
        }
        .assemble()
    }
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
    headers: crate::api::WriteHeaders,
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
