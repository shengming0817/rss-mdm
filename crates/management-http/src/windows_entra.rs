//! Session-authorized organization policy; native consent uses Entra bearer authority separately.
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_windows_channel::entra::{Management, Revision, Settings, Update};
use std::sync::Arc;
type App = Arc<Option<Arc<Management>>>;
pub fn routes(service: Option<Arc<Management>>) -> Router {
    Router::new()
        .route("/windows/entra-policy", get(read).put(update))
        .with_state(Arc::new(service))
}
struct Failure(rss_mdm_windows_channel::Error);
impl From<rss_mdm_windows_channel::Error> for Failure {
    fn from(e: rss_mdm_windows_channel::Error) -> Self {
        Self(e)
    }
}
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}
fn service(app: &App) -> Result<&Management, Failure> {
    app.as_ref()
        .as_deref()
        .ok_or_else(|| rss_mdm_windows_channel::Error::Unsupported.into())
}
async fn read(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
) -> Result<Json<Settings>, Failure> {
    Ok(Json(service(&app)?.settings(&auth.proof).await?))
}
async fn update(
    State(app): State<App>,
    Extension(auth): Extension<RequestAuth>,
    Extension(a): Extension<RequestAudit>,
    body: Result<Json<Update>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Revision>, Failure> {
    let Json(input) = body.map_err(|_| Failure(rss_mdm_windows_channel::Error::Malformed))?;
    Ok(Json(service(&app)?.update(&auth.proof, &input, &a).await?))
}
