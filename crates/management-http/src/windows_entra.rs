//! Session-authorized organization policy; native consent uses Entra bearer authority separately.
use crate::{Error, authorization::context::RequestAuth};
use axum::{Extension, Json, extract::State};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::Router;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_registration_service::windows_entra::{Management, Revision, Settings, Update};
use std::sync::Arc;
type App = Arc<Option<Arc<Management>>>;
pub fn routes(
    service: Option<Arc<Management>>,
) -> Router<(), impl rss_mdm_http_contract::module::Declaration + use<>> {
    register().with_state(Arc::new(service))
}
pub(crate) fn register() -> Router<App, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_read, put_update } }
        RegisterModule1 {
            get_read: rss_mdm_http_contract::module::Route::new(
                "/windows/entra-policy",
                rss_mdm_http_contract::routing::get(
                    read,
                    &contracts::ENTRA_POLICY,
                    &[RouteOperation::Get],
                ),
            ),
            put_update: rss_mdm_http_contract::module::Route::new(
                "/windows/entra-policy",
                rss_mdm_http_contract::routing::put(
                    update,
                    &contracts::ENTRA_POLICY,
                    &[RouteOperation::Update],
                ),
            ),
        }
        .assemble()
    }
}
fn service(app: &App) -> Result<&Management, Error> {
    app.as_ref().as_deref().ok_or(Error::Unsupported)
}
async fn read(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<Settings>, Error> {
    Ok(Json(service(&app)?.settings(&auth.proof).await?))
}
async fn update(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    body: Result<Json<Update>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Revision>, Error> {
    let Json(input) = body.map_err(Error::from)?;
    Ok(Json(service(&app)?.update(&auth.proof, &input, &a).await?))
}
