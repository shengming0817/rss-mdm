use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_http_contract::routing::get;
use rss_mdm_http_contract::{Operation as RouteOperation, Router, catalog as contracts};
use std::sync::Arc;
use uuid::Uuid;
pub fn routes() -> Router<
    Arc<rss_mdm_software_service::deployment::queries::Queries>,
    impl rss_mdm_http_contract::module::Declaration + use<>,
> {
    rss_mdm_http_contract::route_module! {struct Routes for [Browser]{get_rollout}}
    Routes {
        get_rollout: rss_mdm_http_contract::module::Route::new(
            "/policies/{id}/software/rollout",
            get(rollout, &contracts::POLICIES, &[RouteOperation::Action]),
        ),
    }
    .assemble()
}
async fn rollout(
    State(app): State<Arc<rss_mdm_software_service::deployment::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, id)): Path<(uuid::Uuid, Uuid)>,
) -> Result<Json<rss_mdm_software_service::deployment::queries::records::Rollout>, Error> {
    audit.operation(
        id,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    app.software_rollout(&auth.proof, id, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
