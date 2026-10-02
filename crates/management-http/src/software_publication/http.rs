use super::wire;
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    routing::get,
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_software_service::catalog::Operation;
pub(crate) use rss_mdm_software_service::management::publication::{
    model::Change, service::PublicationDirectory,
};
use std::sync::Arc;
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new().route(
        "/software-sources/{source}/candidates/{id}",
        get(read).post(write),
    )
}
async fn read(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((source, id)): Path<(String, String)>,
) -> std::result::Result<Json<wire::Candidate>, Error> {
    rss_mdm_software_service::management::publication::service::read(
        &app.publications,
        &app.access,
        &auth.proof,
        &audit,
        source,
        id,
    )
    .await
    .map(Json)
    .map_err(Into::into)
}
async fn write(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((source, id)): Path<(String, String)>,
    Json(request): Json<Operation<Change>>,
) -> std::result::Result<Json<wire::Candidate>, Error> {
    rss_mdm_software_service::management::publication::service::write(
        &app.publications,
        &app.access,
        &auth.proof,
        &audit,
        source,
        id,
        request,
    )
    .await
    .map(Json)
    .map_err(Into::into)
}
pub struct HttpState {
    pub publications: Arc<PublicationDirectory>,
    pub access: Arc<rss_mdm_authorization_service::Store>,
}
