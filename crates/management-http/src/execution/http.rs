use super::*;
use crate::authorization::context::RequestAuth;
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
    http::StatusCode,
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
use serde_json::Value;
pub fn routes(
    queries: Arc<rss_mdm_execution_service::queries::Queries>,
    cursor: rss_mdm_query::cursor::CursorCodec,
) -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/task-signing/trust/devices/{device}/observation",
            get(task_trust_observation).owned(&contracts::TASK_TRUST, &[RouteOperation::Get]),
        )
        .route(
            "/task-signing/operations/{id}",
            get(task_trust_operation)
                .owned(&contracts::TASK_TRUST_OPERATIONS, &[RouteOperation::Get]),
        )
        .route(
            "/task-signing/trust",
            get(task_trust)
                .owned(&contracts::TASK_TRUST, &[RouteOperation::Get])
                .post(change_task_trust)
                .owned(&contracts::TASK_TRUST, &[RouteOperation::Update]),
        )
        .route(
            "/devices/{device}/recovery-credentials/operations",
            post(create_recovery).owned(
                &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Create],
            ),
        )
        .merge(
            Router::new()
                .route(
                    "/operations",
                    get(directory)
                        .owned(&contracts::EXECUTIONS, &[RouteOperation::List])
                        .queried(&rss_mdm_execution_service::directory::SCHEMA),
                )
                .route(
                    "/operations/statistics",
                    get(statistics).owned(&contracts::EXECUTIONS, &[RouteOperation::Query]),
                )
                .route(
                    "/devices/{device}/ddm",
                    get(ddm)
                        .owned(&contracts::DEVICE_DECLARATIONS, &[RouteOperation::List])
                        .windowed(&rss_mdm_execution_service::queries::ddm::SCHEMA),
                )
                .route(
                    "/devices/{device}/operations/{id}",
                    get(read).owned(&contracts::DEVICES, &[RouteOperation::Action]),
                )
                .layer(Extension(cursor))
                .with_state(queries),
        )
        .route(
            "/devices/{device}/operations",
            post(create).owned(
                &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Create],
            ),
        )
        .route(
            "/devices/{device}/operations/{id}/cancel",
            post(cancel).owned(
                &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
        .route(
            "/devices/{device}/operations/{id}/reauthorize",
            post(reauthorize).owned(
                &contracts::DEVICES,
                &[RouteOperation::Action, RouteOperation::Lifecycle],
            ),
        )
}
async fn directory(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Extension(codec): Extension<rss_mdm_query::cursor::CursorCodec>,
    RawQuery(raw): RawQuery,
) -> std::result::Result<rss_mdm_http_contract::CollectionResponse<Json<Value>>, Error> {
    (async {
        audit.set_action(
            "command_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let q = rss_mdm_execution_service::directory::SCHEMA
            .parse(raw.as_deref().unwrap_or(""))
            .map_err(|_| Error::Malformed)?;
        let mut page = crate::execution::projection::directory(
            s.directory(&auth.proof, &q, &codec, &audit).await?,
        );
        for item in page["items"].as_array_mut().ok_or(Error::Malformed)? {
            *item = q.project(item.take()).map_err(|_| Error::Malformed)?;
        }
        Ok(Json(page))
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
async fn statistics(
    State(s): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    RawQuery(raw): RawQuery,
) -> std::result::Result<Json<Value>, Error> {
    audit.set_action(
        "command_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    let q = rss_mdm_execution_service::directory::SCHEMA
        .statistics(raw.as_deref().unwrap_or(""))
        .map_err(|_| Error::Malformed)?;
    Ok(Json(s.directory_statistics(&auth.proof, &q, &audit).await?))
}
async fn create(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path(device): Path<String>,
    input: std::result::Result<Json<Input>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<(StatusCode, Json<Value>), Error> {
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
        .map(|v| (StatusCode::ACCEPTED, Json(v)))
        .map_err(Error::from)
}
async fn read(
    State(app): State<Arc<rss_mdm_execution_service::queries::Queries>>,
    Extension(auth): Extension<RequestAuth>,
    Extension(audit): Extension<RequestAudit>,
    Path((device, id)): Path<(String, Uuid)>,
) -> std::result::Result<Json<Value>, Error> {
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
) -> std::result::Result<Json<Value>, Error> {
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
) -> std::result::Result<Json<Value>, Error> {
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
    RawQuery(raw): RawQuery,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Value>>, Error> {
    (async {
        let (query, _) = rss_mdm_execution_service::queries::ddm::SCHEMA
            .parse(raw.as_deref().unwrap_or(""))
            .map_err(|_| Error::Malformed)?;
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
) -> Result<(StatusCode, Json<Value>), Error> {
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
        .map(|v| (StatusCode::ACCEPTED, Json(v)))
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
    headers: axum::http::HeaderMap,
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
