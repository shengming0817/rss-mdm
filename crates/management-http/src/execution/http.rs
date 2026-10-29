use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use rss_mdm_execution_service::{
    Change,
    device_control::{Input, Reauthorization},
};
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use rss_mdm_http_contract::{
    Router,
    routing::{get, post},
};
pub fn routes(
    queries: Arc<rss_mdm_execution_service::queries::Queries>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    register(Some(queries), Some(cursor))
}
pub(crate) fn register(
    queries: Option<Arc<rss_mdm_execution_service::queries::Queries>>,
    cursor: Option<rss_mdm_query::cursor::CursorCodec>,
) -> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    let router = {
        rss_mdm_http_contract::route_module! { struct RegisterModule1 for [Browser] { get_task_trust_observation, get_task_trust_operation, get_task_trust, post_change_task_trust, post_create_recovery, router_new, post_create, post_cancel, post_reauthorize } }
        RegisterModule1 { get_task_trust_observation: rss_mdm_http_contract::module::Route::new("/task-signing/trust/devices/{device}/observation", get(task_trust_observation, &contracts::TASK_TRUST, &[RouteOperation::Get])),
get_task_trust_operation: rss_mdm_http_contract::module::Route::new("/task-signing/operations/{id}", get(task_trust_operation, &contracts::TASK_TRUST_OPERATIONS, &[RouteOperation::Get])),
get_task_trust: rss_mdm_http_contract::module::Route::new("/task-signing/trust", rss_mdm_http_contract::routing::get(task_trust, &contracts::TASK_TRUST, &[RouteOperation::Get])),
post_change_task_trust: rss_mdm_http_contract::module::Route::new("/task-signing/trust", rss_mdm_http_contract::routing::post(change_task_trust, &contracts::TASK_TRUST, &[RouteOperation::Update])),
post_create_recovery: rss_mdm_http_contract::module::Route::new("/devices/{device}/recovery-credentials/operations", post(create_recovery, &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Create])),
router_new: {
 rss_mdm_http_contract::route_module! { struct RegisterModule2 for [Browser] { get_directory, get_statistics, get_ddm, get_read } }
 RegisterModule2 { get_directory: rss_mdm_http_contract::module::Route::new("/operations", get(directory, &contracts::EXECUTIONS, &[RouteOperation::List])),
get_statistics: rss_mdm_http_contract::module::Route::new("/operations/statistics", get(statistics, &contracts::EXECUTIONS, &[RouteOperation::Query])),
get_ddm: rss_mdm_http_contract::module::Route::new("/devices/{device}/ddm", get(ddm, &contracts::DEVICE_DECLARATIONS, &[RouteOperation::List])),
get_read: rss_mdm_http_contract::module::Route::new("/devices/{device}/operations/{id}", get(read, &contracts::DEVICES, &[RouteOperation::Action])) }.assemble()
}
                .bind_with(queries.as_ref(), Clone::clone),
post_create: rss_mdm_http_contract::module::Route::new("/devices/{device}/operations", post(create, &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Create])),
post_cancel: rss_mdm_http_contract::module::Route::new("/devices/{device}/operations/{id}/cancel", post(cancel, &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Lifecycle])),
post_reauthorize: rss_mdm_http_contract::module::Route::new("/devices/{device}/operations/{id}/reauthorize", post(reauthorize, &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Lifecycle])) }.assemble()
    };
    match cursor {
        Some(cursor) => router.layer(Extension(cursor)),
        None => router,
    }
}
async fn directory(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Directory<DirectoryQuery>,
    >,
) -> std::result::Result<
    rss_mdm_http_contract::CollectionResponse<
        Json<
            rss_mdm_execution_service::queries::records::Page<
                rss_mdm_query::directory::Projection<super::projection::DirectoryItem>,
                String,
            >,
        >,
    >,
    Error,
> {
    (async {
        audit.set_action(
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = query.parse().map_err(|_| Error::Malformed)?;
        let page = crate::execution::projection::directory(
            s.directory(&auth.proof, &q, &codec, &audit).await?,
        );
        let items = page
            .items
            .into_iter()
            .map(|item| q.project_typed(item).map_err(|_| Error::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Json(rss_mdm_execution_service::queries::records::Page {
            items,
            next_cursor: page.next_cursor,
        }))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn statistics(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    query: rss_mdm_http_contract::query::OwnedQuery<
        rss_mdm_http_contract::query::Statistics<ExecutionStatisticsQuery>,
    >,
) -> std::result::Result<
    Json<
        rss_mdm_query::Statistics<rss_mdm_execution_service::queries::records::ExecutionStatistics>,
    >,
    Error,
> {
    audit.set_action(
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let q = query.parse().map_err(|_| Error::Malformed)?;
    Ok(Json(s.directory_statistics(&auth.proof, &q, &audit).await?))
}
async fn create(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: std::result::Result<Json<Input>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<
    rss_mdm_http_contract::signature::WithStatus<
        202,
        Json<rss_mdm_execution_service::AcceptedReceipt>,
    >,
    Error,
> {
    let input = input.map_err(Error::from)?.0;
    audit.operation(
        input.operation_id,
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    app.execution
        .create_control(&auth.proof, &device, &input, &audit)
        .await
        .map(|v| rss_mdm_http_contract::signature::WithStatus(Json(v)))
        .map_err(Error::from)
}
async fn read(
    State(app): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
) -> std::result::Result<
    Json<
        rss_mdm_execution_service::queries::records::CommandDetail<super::projection::Observation>,
    >,
    Error,
> {
    audit.operation(
        id,
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.target_device(&device);
    app.read(&auth.proof, &device, id, &audit)
        .await
        .map(|v| Json(crate::execution::projection::command(v)))
        .map_err(Error::from)
}
async fn cancel(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    input: std::result::Result<Json<Change>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<rss_mdm_execution_service::ChangedReceipt>, Error> {
    let change = input.map_err(Error::from)?.0;
    audit.operation(
        change.request_id,
        "command_cancel",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    app.execution
        .change(&auth.proof, &device, id, &change, None, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn reauthorize(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
    input: std::result::Result<Json<Reauthorization>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<Json<rss_mdm_execution_service::ChangedReceipt>, Error> {
    let change = input.map_err(Error::from)?.0;
    let revision = Change {
        request_id: change.request_id,
        expected_revision: change.expected_revision,
    };
    audit.operation(
        change.request_id,
        "command_reauthorize",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    app.execution
        .change(&auth.proof, &device, id, &revision, Some(&change), &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}

pub struct HttpState {
    pub execution: std::sync::Arc<rss_mdm_execution_service::ExecutionService>,
    pub apple: bool,
    pub windows: bool,
}
impl HttpState {
    pub fn apple(&self) -> std::result::Result<(), crate::Error> {
        self.apple.then_some(()).ok_or(crate::Error::Unsupported)
    }
}
impl HttpState {
    pub fn windows(&self) -> std::result::Result<(), crate::Error> {
        self.windows.then_some(()).ok_or(crate::Error::Unsupported)
    }
}

async fn ddm(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
    query: rss_mdm_http_contract::query::OwnedQuery<rss_mdm_http_contract::query::Window<DdmQuery>>,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<super::projection::Ddm>>, Error> {
    (async {
        let (query, _) = query.parse().map_err(|_| Error::Malformed)?;
        Ok(Json(crate::execution::projection::ddm(
            s.ddm(&auth.proof, &device, &query, &audit, &codec).await?,
        )))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn create_recovery(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: Result<
        Json<rss_mdm_execution_service::recovery_credentials::Input>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<
    rss_mdm_http_contract::signature::WithStatus<
        202,
        Json<rss_mdm_execution_service::AcceptedReceipt>,
    >,
    Error,
> {
    let input = input.map_err(Error::from)?.0;
    audit.operation(
        input.operation_id,
        "command_accept",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(&device);
    app.execution
        .create_recovery_credential(&auth.proof, &device, &input, &audit)
        .await
        .map(|v| rss_mdm_http_contract::signature::WithStatus(Json(v)))
        .map_err(Error::from)
}

async fn task_trust(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
) -> std::result::Result<Json<rss_mdm_agent_wire::task_trust::Trust>, Error> {
    app.execution
        .task_trust(&auth.proof, &audit)
        .await
        .map(Json)
        .map_err(Error::from)
}
async fn change_task_trust(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    headers: crate::api::WriteHeaders,
    input: std::result::Result<
        Json<rss_mdm_execution_service::task_signing::service::Change>,
        axum::extract::rejection::JsonRejection,
    >,
) -> std::result::Result<Json<rss_mdm_agent_wire::task_trust::Trust>, Error> {
    let operation = crate::api::write_key(&headers, &audit, "task_signing_change")?;
    let input = input.map_err(Error::from)?.0;
    app.execution
        .change_task_trust(&auth.proof, &audit, operation, &input)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn task_trust_operation(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<rss_mdm_agent_wire::task_trust::Trust>, Error> {
    app.execution
        .task_trust_operation(&auth.proof, &audit, id)
        .await
        .map(Json)
        .map_err(Error::from)
}

async fn task_trust_observation(
    State(s): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
) -> std::result::Result<Json<Option<rss_mdm_agent_wire::task_trust::ObservedInstallation>>, Error>
{
    s.execution
        .task_trust_observation(&auth.proof, &audit, &device)
        .await
        .map(Json)
        .map_err(Error::from)
}

struct DirectoryQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for DirectoryQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_execution_service::directory::SCHEMA
    }
}

struct DdmQuery;
impl rss_mdm_http_contract::query::WindowOwner for DdmQuery {
    fn schema() -> &'static rss_mdm_query::window::Schema {
        &rss_mdm_execution_service::queries::ddm::SCHEMA
    }
}

struct ExecutionStatisticsQuery;
impl rss_mdm_http_contract::query::DirectoryOwner for ExecutionStatisticsQuery {
    fn schema() -> &'static rss_mdm_query::directory::Schema {
        &rss_mdm_execution_service::directory::SCHEMA
    }
}
