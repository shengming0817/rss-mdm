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
pub fn routes()
-> Router<Arc<rss_mdm_task_trust::Service>, impl rss_mdm_http_contract::module::Declaration + use<>>
{
    rss_mdm_http_contract::route_module! {struct Routes for [Browser]{get_task_trust_observation,get_task_trust_operation,get_task_trust,post_change_task_trust}}
    Routes {
        get_task_trust_observation: rss_mdm_http_contract::module::Route::new(
            "/task-signing/trust/devices/{device}/observation",
            get(
                task_trust_observation,
                &contracts::TASK_TRUST,
                &[RouteOperation::Get],
            ),
        ),
        get_task_trust_operation: rss_mdm_http_contract::module::Route::new(
            "/task-signing/operations/{id}",
            get(
                task_trust_operation,
                &contracts::TASK_TRUST_OPERATIONS,
                &[RouteOperation::Get],
            ),
        ),
        get_task_trust: rss_mdm_http_contract::module::Route::new(
            "/task-signing/trust",
            rss_mdm_http_contract::routing::get(
                task_trust,
                &contracts::TASK_TRUST,
                &[RouteOperation::Get],
            ),
        ),
        post_change_task_trust: rss_mdm_http_contract::module::Route::new(
            "/task-signing/trust",
            rss_mdm_http_contract::routing::post(
                change_task_trust,
                &contracts::TASK_TRUST,
                &[RouteOperation::Update],
            ),
        ),
    }
    .assemble()
}
async fn task_trust(
    axum::extract::Path(_tenant): axum::extract::Path<uuid::Uuid>,

    State(app): State<Arc<rss_mdm_task_trust::Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> std::result::Result<Json<rss_mdm_agent_wire::task_trust::Trust>, Error> {
    app.task_trust(&auth.proof, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn change_task_trust(
    axum::extract::Path(_tenant): axum::extract::Path<uuid::Uuid>,

    State(app): State<Arc<rss_mdm_task_trust::Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    input: std::result::Result<
        Json<rss_mdm_task_trust::service::Change>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<rss_mdm_agent_wire::task_trust::Trust>, Error> {
    let operation = crate::api::write_key(&headers, &audit, "task_signing_change")?;
    let input = input.map_err(Error::from)?.0;
    app.change_task_trust(&auth.proof, &audit, operation, &input)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn task_trust_operation(
    State(app): State<Arc<rss_mdm_task_trust::Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, id)): Path<(uuid::Uuid, Uuid)>,
) -> std::result::Result<Json<rss_mdm_agent_wire::task_trust::Trust>, Error> {
    app.task_trust_operation(&auth.proof, &audit, id)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn task_trust_observation(
    State(s): State<Arc<rss_mdm_task_trust::Service>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, device)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId)>,
) -> std::result::Result<Json<Option<rss_mdm_agent_wire::task_trust::ObservedInstallation>>, Error>
{
    s.task_trust_observation(&auth.proof, &audit, &device)
        .await
        .map(Json)
        .map_err(Error::from)
}
