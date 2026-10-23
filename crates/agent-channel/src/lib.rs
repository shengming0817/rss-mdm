//! Agent runtime V1 ingress; request fields carry no tenant or registration authority.
mod diagnostic;
mod error;
pub use diagnostic::{ConfigIssue, Failure};
pub use error::Error;
use error::Missing;
use rss_mdm_inventory_service::collection;
use rss_mdm_registration_service::{device, enrollment};
mod bindings;
mod database;
pub mod enroll;
pub use bindings::Bindings;
pub use database::Store;
mod content;
mod operations;
mod tasks;
mod telemetry;
pub fn router(state: Arc<HttpState>, envelope: boundary::Envelope) -> Router {
    boundary::wrap(routes().with_state(state), envelope)
}
pub fn task_router(state: Arc<TaskState>, envelope: boundary::Envelope) -> Router {
    boundary::wrap(tasks::routes().with_state(state), envelope)
}
pub fn installation_router(
    execution: Arc<rss_mdm_execution_service::ExecutionService>,
    envelope: boundary::Envelope,
) -> Router {
    boundary::wrap_enroll(tasks::installation_routes().with_state(execution), envelope)
}
pub use tasks::TaskState;

use crate::database::db;
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_inventory::ReportSource as InventorySource;
use rss_observation::{Batch, Body, Change, Id};
use rss_request_context::TenantId;
use serde_json::Value;
use std::{future::Future, sync::Arc, time::Duration};
use uuid::Uuid;

fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/reports", post(report))
        .route("/reports/{id}", get(status))
        .merge(telemetry::routes())
}

#[derive(Clone)]
pub(crate) enum AgentError {
    Wire(wire::ErrorCode),
    Enrollment(rss_mdm_agent_wire::enroll::ErrorCode),
    Service(Error),
}
impl From<Error> for AgentError {
    fn from(value: Error) -> Self {
        Self::Service(value)
    }
}
impl IntoResponse for AgentError {
    fn into_response(self) -> Response {
        if let Self::Enrollment(code) | Self::Service(Error::Agent(code)) = self {
            return credential_response(code);
        }
        let (status, code, app_error) = match self {
            Self::Enrollment(_) => unreachable!(),
            Self::Wire(code) => (status_for(code), code, None),
            Self::Service(error) => {
                let code = match error {
                    Error::Agent(_) => unreachable!(),
                    Error::Malformed | Error::CertificateRequest => {
                        wire::ErrorCode::MalformedRequest
                    }
                    Error::Conflict => wire::ErrorCode::OperationConflict,
                    Error::CommitUnknown | Error::RollbackFailed => {
                        wire::ErrorCode::OperationUnknown
                    }
                    Error::Unauthorized | Error::Forbidden => wire::ErrorCode::InvalidIdentity,
                    Error::Missing(Missing::Task) => wire::ErrorCode::TaskNotFound,
                    Error::Missing(_) | Error::NotFound => wire::ErrorCode::ReportNotFound,
                    Error::Configuration(_) | Error::Unavailable(_) | Error::Unsupported => {
                        wire::ErrorCode::ServiceUnavailable
                    }
                };
                (status_for(code), code, Some(error))
            }
        };
        let mut response = (status, Json(wire::ErrorBody { code })).into_response();
        response.extensions_mut().insert(wire::ErrorBody { code });
        if let Some(error) = app_error {
            response.extensions_mut().insert(error);
        }
        response
    }
}
fn status_for(code: wire::ErrorCode) -> StatusCode {
    match code {
        wire::ErrorCode::MalformedRequest
        | wire::ErrorCode::UnsupportedWire
        | wire::ErrorCode::UnsupportedCapability => StatusCode::BAD_REQUEST,
        wire::ErrorCode::InvalidIdentity
        | wire::ErrorCode::CredentialRevoked
        | wire::ErrorCode::CertificateExpired
        | wire::ErrorCode::CredentialRetired => StatusCode::UNAUTHORIZED,
        wire::ErrorCode::ReportNotFound | wire::ErrorCode::TaskNotFound => StatusCode::NOT_FOUND,
        wire::ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
        wire::ErrorCode::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
        wire::ErrorCode::OperationConflict => StatusCode::CONFLICT,
        wire::ErrorCode::OperationUnknown | wire::ErrorCode::ServiceUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

pub(crate) async fn bounded<T>(
    work: impl Future<Output = Result<T, AgentError>>,
) -> Result<T, AgentError> {
    bounded_for(Duration::from_secs(8), work).await
}
async fn bounded_for<T>(
    budget: Duration,
    work: impl Future<Output = Result<T, AgentError>>,
) -> Result<T, AgentError> {
    tokio::time::timeout(budget, work)
        .await
        .map_err(|_| AgentError::Service(Error::Unavailable(Failure::RequestDeadline)))?
}

pub fn ingress_error(code: wire::ErrorCode) -> Response {
    AgentError::Wire(code).into_response()
}

async fn report(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<wire::ReportAck>), AgentError> {
    json_content_type(&headers)?;
    let body = body.map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    bounded(report_inner(
        &app,
        &audit,
        &headers,
        peer.as_ref().map(|p| &p.0),
        body,
    ))
    .await
}
async fn report_inner(
    app: &HttpState,
    audit: &RequestAudit,
    headers: &HeaderMap,
    peer: Option<&rss_mdm_certificate::ClientCertificateEvidence>,
    body: Bytes,
) -> Result<(StatusCode, Json<wire::ReportAck>), AgentError> {
    let input = parse_report(&body)?;
    let principal = authenticate(&app.enrollment, headers, peer).await?;
    let scope = device::scope(
        principal.tenant(),
        principal.registration(),
        InventorySource::AgentBuiltin.as_str(),
        principal.epoch(),
    )
    .map_err(Error::from)?;
    audit.set_action("agent_report");
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    let scope = crate::device::scope_dataset(
        principal.tenant(),
        principal.registration(),
        InventorySource::AgentBuiltin.as_str(),
        Uuid::parse_str(scope.epoch().as_str()).map_err(|_| Error::Malformed)?,
        input.collection().dataset(),
    )
    .map_err(Error::from)?;
    let batch = batch(&input)?;
    let fingerprint: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(input.canonical().map_err(|_| Error::Malformed)?).into()
    };
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
    let attempt = app.audit_store.write(principal.tenant(),
            &budget.source_control(),
        (&app.audit_store, &principal, &scope, &input, &batch, audit, &fingerprint),
        |(store, principal, scope, input, batch, audit, fingerprint), tx| Box::pin(async move {
            let (received_at, fresh) = tx.with_connection_context(&mut (*principal, *scope, *input, *batch),
                |(principal, scope, input, batch), c| Box::pin(async move {crate::bindings::inventory_in(c,principal).await?;let accepted=crate::collection::agent::accept_in(c,principal,scope,batch,input).await.map_err(Error::from)?;crate::device::store::record_communication_in(c,principal).await?;Ok::<_,Error>(accepted)})).await?;
            let result = match input.body() { wire::ReportBody::Snapshot(_) => "snapshot", wire::ReportBody::Partial(_) => "partial", wire::ReportBody::Failed { .. } => "failed" };
            let fact = rss_mdm_audit_integration::Fact::business(audit,
                &format!("agent-report:{}", input.report_id()), fingerprint.as_slice(), 202, "success", None)
                .and_then(|fact| fact.with_details(serde_json::json!({"reportId":input.report_id(),"collectionResult":result,"receivedAt":received_at})))
                .map_err(Error::from)?;
            store.append(tx, &fact, !fresh).await.map_err(Error::from)?;
            if !fresh { audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed); }
            audit.mark_commit_started();
            Ok(received_at)
        }),
    ).await;
    let received_at = crate::operations::settle(attempt, audit)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ack(input.report_id(), received_at)),
    ))
}

async fn status(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<wire::ReportStatus>, AgentError> {
    let id =
        Uuid::parse_str(&id).map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    bounded(status_inner(
        &app,
        &audit,
        &headers,
        peer.as_ref().map(|p| &p.0),
        id,
    ))
    .await
}
async fn status_inner(
    app: &HttpState,
    audit: &RequestAudit,
    headers: &HeaderMap,
    peer: Option<&rss_mdm_certificate::ClientCertificateEvidence>,
    id: Uuid,
) -> Result<Json<wire::ReportStatus>, AgentError> {
    if id.is_nil() {
        return Err(Error::Malformed.into());
    }
    let principal = authenticate(&app.enrollment, headers, peer).await?;
    let scope = device::scope(
        principal.tenant(),
        principal.registration(),
        InventorySource::AgentBuiltin.as_str(),
        principal.epoch(),
    )
    .map_err(Error::from)?;
    audit.set_action("agent_report_read");
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    let mut tx = app.access.begin(&principal.tenant().to_string()).await?;
    let live_scope =
        crate::device::store::revalidate_source(&mut tx, &principal, InventorySource::AgentBuiltin)
            .await?;
    if live_scope != scope {
        return Err(Error::Unauthorized.into());
    }
    crate::bindings::inventory_in(&mut tx, &principal).await?;
    let (report, received_at) = crate::collection::store::agent_report_in(&mut tx, &scope, id)
        .await?
        .ok_or(AgentError::Wire(wire::ErrorCode::ReportNotFound))?;
    tx.commit().await.map_err(db)?;
    let delivery = app
        .inventory
        .inspect_report(report.scope(), report.batch())
        .await?;
    let (observation, projection) = projection_status(delivery)?;
    Ok(Json(wire::ReportStatus {
        ack: ack(id, received_at),
        observation,
        projection,
    }))
}

fn projection_status(
    delivery: rss_mdm_inventory_service::inventory_runtime::DeliveryStatus,
) -> Result<(wire::ObservationStatus, wire::ProjectionStatus), AgentError> {
    let observation = match delivery.receipt.as_ref().map(|r| r.decision.outcome()) {
        None => wire::ObservationStatus::Pending,
        Some(rss_observation::SyncOutcome::Snapshot) => wire::ObservationStatus::Snapshot,
        Some(rss_observation::SyncOutcome::Stale) => wire::ObservationStatus::Stale,
        Some(rss_observation::SyncOutcome::NeedSnapshot(
            rss_observation::NeedSnapshot::CollectionFailed,
        )) => wire::ObservationStatus::NeedSnapshotCollectionFailed,
        Some(rss_observation::SyncOutcome::NeedSnapshot(_)) => {
            wire::ObservationStatus::NeedSnapshotPartial
        }
        Some(rss_observation::SyncOutcome::Delta) => {
            return Err(Error::Unavailable(Failure::InventoryRuntime).into());
        }
    };
    let projection = match delivery.projection {
        rss_mdm_inventory_service::inventory_runtime::ProjectionStatus::Projected => {
            wire::ProjectionStatus::Applied
        }
        rss_mdm_inventory_service::inventory_runtime::ProjectionStatus::NotApplicable => {
            wire::ProjectionStatus::NotApplicable
        }
        rss_mdm_inventory_service::inventory_runtime::ProjectionStatus::Pending
        | rss_mdm_inventory_service::inventory_runtime::ProjectionStatus::PendingReceipt => {
            wire::ProjectionStatus::Pending
        }
    };
    Ok((observation, projection))
}

fn json_content_type(headers: &HeaderMap) -> Result<(), AgentError> {
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some("application/json")
    {
        return Err(AgentError::Wire(wire::ErrorCode::MalformedRequest));
    }
    Ok(())
}
fn parse_report(body: &[u8]) -> Result<wire::ReportRequest, AgentError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    let version = value
        .get("wireVersion")
        .and_then(Value::as_u64)
        .ok_or(AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    if version != u64::from(wire::WIRE_VERSION) {
        return Err(AgentError::Wire(wire::ErrorCode::UnsupportedWire));
    }
    serde_json::from_value(value).map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))
}
pub(crate) async fn authenticate(
    service: &rss_mdm_registration_service::agent::Service,
    headers: &HeaderMap,
    peer: Option<&rss_mdm_certificate::ClientCertificateEvidence>,
) -> Result<device::DevicePrincipal, AgentError> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(Error::Unauthorized.into());
    }
    service
        .authenticate(peer.ok_or(Error::Unauthorized)?)
        .await
        .map_err(|e| AgentError::Enrollment(e.code))
}
fn batch(input: &wire::ReportRequest) -> Result<Batch, AgentError> {
    let definition = collection::wire::to_domain(input.collection())?;
    let changes = input
        .values()
        .iter()
        .filter(|item| input.collection().field(item.field).is_ok())
        .map(|item| {
            let projected = item
                .value
                .project(
                    input
                        .collection()
                        .field(item.field)
                        .map_err(|_| Error::Malformed)?,
                )
                .map_err(|_| Error::Malformed)?;
            let key = rss_mdm_inventory::FieldKey::parse(item.field.as_str())
                .map_err(|_| Error::Malformed)?;
            let field = definition.field(key).map_err(|_| Error::Malformed)?;
            Ok(Change::upsert(
                Id::new(item.field.as_str()).map_err(|_| Error::Malformed)?,
                collection::wire::value(&projected)
                    .encode(field)
                    .map_err(|_| Error::Malformed)?,
            ))
        })
        .collect::<Result<Vec<_>, AgentError>>()?;
    let body = match input.body() {
        wire::ReportBody::Snapshot(_) => Body::Snapshot(changes),
        wire::ReportBody::Partial(_) => Body::Partial(changes),
        wire::ReportBody::Failed { code } => Body::Failed {
            code: Id::new(match code {
                wire::FailureCode::PermissionDenied => "permission_denied",
                wire::FailureCode::TemporarilyUnavailable => "temporarily_unavailable",
                wire::FailureCode::CollectionFailed => "collection_failed",
            })
            .expect("fixed failure"),
        },
    };
    Batch::new(
        Id::new(input.report_id().to_string()).map_err(|_| Error::Malformed)?,
        input.sequence(),
        rss_contract::Timepoint::try_from(input.observed_at()).map_err(|_| Error::Malformed)?,
        definition.coverage().map_err(|_| Error::Malformed)?,
        body,
    )
    .map_err(|_| Error::Malformed.into())
}

fn ack(report_id: Uuid, received_at: i64) -> wire::ReportAck {
    wire::ReportAck {
        wire_version: wire::WIRE_VERSION,
        report_id,
        received_at,
        intake: wire::IntakeStatus::Durable,
    }
}

pub struct HttpState {
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub telemetry: Option<Arc<rss_mdm_telemetry_service::Service>>,
    pub enrollment: Arc<rss_mdm_registration_service::agent::Service>,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub access: Arc<crate::database::Store>,
    pub inventory: Arc<rss_mdm_inventory_service::inventory_runtime::InventoryRuntime>,
}

impl From<crate::enrollment::EnrollmentError> for AgentError {
    fn from(error: crate::enrollment::EnrollmentError) -> Self {
        Error::from(error).into()
    }
}

#[cfg(test)]
#[path = "../tests/unit.rs"]
mod tests;

impl From<rss_mdm_authorization_service::Error> for AgentError {
    fn from(error: rss_mdm_authorization_service::Error) -> Self {
        Self::from(Error::from(error))
    }
}

impl From<rss_mdm_registration_service::Error> for AgentError {
    fn from(e: rss_mdm_registration_service::Error) -> Self {
        Self::from(Error::from(e))
    }
}

impl From<rss_mdm_inventory_service::Error> for AgentError {
    fn from(e: rss_mdm_inventory_service::Error) -> Self {
        Self::from(Error::from(e))
    }
}

/// Fresh product schema owned by this capability.
pub const INSTALL_SQL: &str = include_str!("../schema/install.sql");
/// Cross-owner references and exact runtime privileges; apply after all owner tables.
pub const RELATIONS_SQL: &str = include_str!("../schema/relations.sql");

pub mod boundary;

/// This capability's closed privileges in the shared access connection.
pub const ACCESS_CONTRACT: &str = include_str!("access-contract.json");

async fn builtin_collections(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    registration: Uuid,
    epoch: Uuid,
) -> Result<Vec<wire::CollectionDefinition>, Error> {
    let key = rss_mdm_inventory::builtin::MDM_ENROLLMENT;
    let scope = device::scope_dataset(
        tenant,
        registration,
        InventorySource::AgentBuiltin.as_str(),
        epoch,
        key.as_str(),
    )?;
    Ok(vec![collection::wire::to_wire(
        &collection::store::freeze_in(c, &scope, 1, &[key]).await?,
    )?])
}

impl From<rss_mdm_execution_service::Error> for AgentError {
    fn from(e: rss_mdm_execution_service::Error) -> Self {
        Self::Service(e.into())
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        AgentError::Service(self).into_response()
    }
}

fn credential_response(code: rss_mdm_agent_wire::enroll::ErrorCode) -> Response {
    use rss_mdm_agent_wire::enroll::ErrorCode as C;
    let code = match code {
        C::CredentialRevoked => wire::ErrorCode::CredentialRevoked,
        C::CertificateExpired => wire::ErrorCode::CertificateExpired,
        C::CredentialRetired => wire::ErrorCode::CredentialRetired,
        C::PermissionDenied => wire::ErrorCode::PermissionDenied,
        C::ServiceUnavailable | C::ActivationUnknown => wire::ErrorCode::ServiceUnavailable,
        _ => wire::ErrorCode::InvalidIdentity,
    };
    (status_for(code), Json(wire::ErrorBody { code })).into_response()
}
