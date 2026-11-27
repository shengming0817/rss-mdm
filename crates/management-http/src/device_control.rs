use crate::Pending;
use crate::{Error, authorization::context::RequestAuth};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_device_service::control::{
    Change,
    device_control::{Input, Reauthorization},
};
use rss_mdm_http_contract::routing::post;
use rss_mdm_http_contract::{Operation as RouteOperation, Router, catalog as contracts};
use std::sync::Arc;
use uuid::Uuid;
pub trait Changes: Send + Sync {
    fn change<'a>(
        &'a self,
        proof: &'a RequestAuth,
        device: &'a rss_mdm_agent_wire::DeviceId,
        id: Uuid,
        change: &'a rss_mdm_device_service::control::Change,
        reauthorization: Option<
            &'a rss_mdm_device_service::control::device_control::Reauthorization,
        >,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_device_service::control::ChangedReceipt>;
}
pub struct Services {
    pub device_control: Arc<rss_mdm_device_service::control::Service>,
    pub changes: Arc<dyn Changes>,
}
pub fn routes() -> Router<Arc<Services>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    rss_mdm_http_contract::route_module! {struct Routes for [Browser]{post_create,post_cancel,post_reauthorize}}
    Routes {
        post_create: rss_mdm_http_contract::module::Route::new(
            "/devices/{device}/operations",
            post(
                create,
                &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Create],
            ),
        ),
        post_cancel: rss_mdm_http_contract::module::Route::new(
            "/devices/{device}/operations/{id}/cancel",
            post(
                cancel,
                &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        ),
        post_reauthorize: rss_mdm_http_contract::module::Route::new(
            "/devices/{device}/operations/{id}/reauthorize",
            post(
                reauthorize,
                &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        ),
    }
    .assemble()
}
async fn create(
    State(app): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, device)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId)>,
    input: std::result::Result<Json<Input>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<
    rss_mdm_http_contract::signature::WithStatus<
        202,
        Json<rss_mdm_device_service::control::AcceptedReceipt>,
    >,
    Error,
> {
    let input = input.map_err(Error::from)?.0;
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::DeviceControl,
        input.operation_id,
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    app.device_control
        .create_control(&auth.proof, &device, &input, &audit)
        .await
        .map(|v| rss_mdm_http_contract::signature::WithStatus(Json(v)))
        .map_err(Error::from)
}

async fn cancel(
    State(app): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
    input: std::result::Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<rss_mdm_device_service::control::ChangedReceipt>, Error> {
    let change = input.map_err(Error::from)?.0;
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::DeviceControlRequest,
        change.request_id,
        "command_cancel",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    app.changes
        .change(&auth, &device, id, &change, None, &audit)
        .await
        .map(Json)
}

async fn reauthorize(
    State(app): State<Arc<Services>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((_tenant, device, id)): Path<(uuid::Uuid, rss_mdm_agent_wire::DeviceId, Uuid)>,
    input: std::result::Result<Json<Reauthorization>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<rss_mdm_device_service::control::ChangedReceipt>, Error> {
    let change = input.map_err(Error::from)?.0;
    let revision = Change {
        request_id: change.request_id,
        expected_revision: change.expected_revision,
    };
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::DeviceControlRequest,
        change.request_id,
        "command_reauthorize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    app.changes
        .change(&auth, &device, id, &revision, Some(&change), &audit)
        .await
        .map(Json)
}
