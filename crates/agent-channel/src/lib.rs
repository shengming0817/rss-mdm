//! Agent V3 ingress; request fields carry no tenant or registration authority.
use rss_mdm_authorization_service as authorization;
pub use rss_mdm_flow_service::{Error, Failure};
use rss_mdm_inventory_service::collection;
use rss_mdm_registration_service::{device, enrollment};
mod bindings;
mod database;
pub use bindings::Bindings;
pub use database::Store;
mod content;
mod operations;
mod tasks;
pub fn router(state: Arc<HttpState>, envelope: boundary::Envelope) -> Router {
    boundary::wrap(routes().with_state(state), envelope)
}
pub fn task_router(state: Arc<TaskState>, envelope: boundary::Envelope) -> Router {
    boundary::wrap(tasks::routes().with_state(state), envelope)
}
pub use tasks::TaskState;

use crate::{
    database::db,
    device::{BindRegistration, VerifiedChannelCredential},
    enrollment::Password,
    operations::Actor,
    operations::Operation,
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rss_mdm_agent_wire as wire;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_inventory::{FieldKey, ReportSource as InventorySource};
use rss_observation::{Batch, Body, Change, Id};
use rss_request_context::TenantId;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc, time::Duration};
use uuid::Uuid;

fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route("/registrations", post(register))
        .route("/reports", post(report))
        .route("/reports/{id}", get(status))
}

#[derive(Clone)]
pub enum AgentError {
    Wire(wire::ErrorCode),
    Service(Error),
}
impl From<Error> for AgentError {
    fn from(value: Error) -> Self {
        Self::Service(value)
    }
}
impl IntoResponse for AgentError {
    fn into_response(self) -> Response {
        let (status, code, app_error) = match self {
            Self::Wire(code) => (status_for(code), code, None),
            Self::Service(error) => {
                let code = match error {
                    Error::Malformed | Error::CertificateRequest => {
                        wire::ErrorCode::MalformedRequest
                    }
                    Error::Conflict => wire::ErrorCode::OperationConflict,
                    Error::CommitUnknown | Error::RollbackFailed => {
                        wire::ErrorCode::OperationUnknown
                    }
                    Error::Unauthorized | Error::Forbidden => wire::ErrorCode::InvalidIdentity,
                    Error::Execution(
                        rss_mdm_flow_service::execution::error::ExecutionError::MissingTask,
                    ) => wire::ErrorCode::TaskNotFound,
                    Error::NotFound
                    | Error::Resource(_)
                    | Error::Execution(
                        rss_mdm_flow_service::execution::error::ExecutionError::MissingOperation,
                    )
                    | Error::Publication(_)
                    | Error::Planning(
                        rss_mdm_flow_service::planning::error::PlanningError::Missing(_),
                    ) => wire::ErrorCode::ReportNotFound,
                    Error::Configuration(_) | Error::Unavailable(_) | Error::Unsupported => {
                        wire::ErrorCode::ServiceUnavailable
                    }
                };
                (status_for(code), code, Some(error))
            }
        };
        let mut response = (status, Json(wire::ErrorBody { code })).into_response();
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
        wire::ErrorCode::InvalidIdentity => StatusCode::UNAUTHORIZED,
        wire::ErrorCode::ReportNotFound | wire::ErrorCode::TaskNotFound => StatusCode::NOT_FOUND,
        wire::ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
        wire::ErrorCode::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
        wire::ErrorCode::OperationConflict => StatusCode::CONFLICT,
        wire::ErrorCode::OperationUnknown | wire::ErrorCode::ServiceUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

pub async fn bounded<T>(
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

async fn register(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<wire::RegistrationReceipt>), AgentError> {
    json_content_type(&headers)?;
    let body = body.map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    bounded(register_inner(&app, &audit, body)).await
}
async fn register_inner(
    app: &HttpState,
    audit: &RequestAudit,
    body: Bytes,
) -> Result<(StatusCode, Json<wire::RegistrationReceipt>), AgentError> {
    let input = parse_registration(&body)?;
    audit.set_action("agent_registration");
    audit.operation(input.operation_id(), "agent_registration");
    let password = Password::new(input.password().expose().to_owned())?;
    let auth = crate::enrollment::store::enrollment_authorization(
        &app.access.registration(),
        &app.identity.tenant().to_string(),
        input.enrollment_id(),
        &password,
    )
    .await?;
    if auth.source != InventorySource::AgentBuiltin {
        return Err(Error::Unauthorized.into());
    }
    let proof = app
        .identity
        .authenticate(
            &app.access.authorization,
            app.credentials.get(auth.credential_ref)?,
        )
        .await?;
    if proof.principal_id() != auth.actor || proof.instance_id() != auth.instance {
        return Err(Error::Unauthorized.into());
    }
    proof.enrollment(&auth.device)?;
    proof.bind_audit(audit)?;
    audit.target(&auth.device);
    let credential = credential(&app.mount, input.credential());
    let digest = registration_digest(&input);
    let operation = Operation {
        actor: Actor::from_authorized(&proof),
        key: input.operation_id(),
        digest: &digest,
    };
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
    let control = budget.control();
    let attempt = app
        .audit_store
        .write(
            TenantId::parse(proof.tenant_id()).map_err(|_| Error::Malformed)?,
            &control,
            (
                &app.audit_store,
                RegistrationInputs {
                    devices: &app.devices,
                    proof: &proof,
                    auth: &auth,
                    input: &input,
                    credential: &credential,
                    operation: &operation,
                    audit,
                    facts: Vec::new(),
                },
            ),
            |(store, inputs), tx| {
                Box::pin(async move {
                    let (receipt, replayed) = tx
                        .with_connection_context(inputs, |inputs, c| {
                            Box::pin(register_on(c, inputs))
                        })
                        .await?;
                    for fact in &inputs.facts {
                        store.append(tx, fact, false).await.map_err(Error::from)?;
                    }
                    let fact = rss_mdm_audit_integration::Fact::business(
                        inputs.audit,
                        &format!(
                            "agent-registration:{}:{}",
                            inputs.proof.principal_id(),
                            inputs.operation.key
                        ),
                        inputs.operation.digest.as_bytes(),
                        201,
                        "success",
                        Some(inputs.auth.id),
                    )
                    .map_err(Error::from)?;
                    store
                        .append(tx, &fact, replayed)
                        .await
                        .map_err(Error::from)?;
                    if replayed {
                        inputs.audit.management_result(
                            rss_mdm_audit_integration::ManagementResult::Replayed,
                        );
                    }
                    inputs.audit.mark_commit_started();
                    Ok((
                        if replayed {
                            StatusCode::OK
                        } else {
                            StatusCode::CREATED
                        },
                        receipt,
                    ))
                })
            },
        )
        .await;
    let (status, receipt) = crate::operations::settle(attempt, audit)?;
    Ok((status, Json(receipt)))
}

struct RegistrationInputs<'a> {
    devices: &'a crate::device::DeviceService,
    proof: &'a crate::authorization::context::AuthorizedPrincipal,
    auth: &'a crate::enrollment::Authorization,
    input: &'a wire::RegistrationRequest,
    credential: &'a VerifiedChannelCredential,
    operation: &'a Operation<'a>,
    audit: &'a RequestAudit,
    facts: Vec<rss_mdm_audit_integration::Fact>,
}
async fn register_on(
    tx: &mut sqlx::PgConnection,
    context: &mut RegistrationInputs<'_>,
) -> Result<(wire::RegistrationReceipt, bool), Error> {
    let RegistrationInputs {
        devices,
        proof,
        auth,
        input,
        credential,
        operation,
        audit,
        facts,
    } = context;
    let proof = *proof;
    let auth = *auth;
    let input = *input;
    let credential = *credential;
    let audit = *audit;
    let operation = *operation;
    if let Some(old) = crate::operations::replay(tx, operation).await? {
        let receipt: wire::RegistrationReceipt =
            serde_json::from_str(&old).map_err(|_| Error::Unavailable(Failure::Database))?;
        if crate::enrollment::store::active_registration(tx, proof.tenant_id(), auth.id).await?
            != receipt.registration_id
        {
            return Err(Error::Conflict);
        }
        proof.enrollment(&auth.device)?;
        audit.registration(receipt.registration_id);
        return Ok((receipt, true));
    }
    let receipt = devices
        .bind_in(
            tx,
            proof,
            credential,
            &BindRegistration {
                operation_id: input.operation_id(),
                request_id: input.enrollment_id(),
                expected_generation: auth.expected_generation,
                source: InventorySource::AgentBuiltin,
            },
            auth.device.clone(),
            [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
            facts,
        )
        .await?;
    let capabilities = serde_json::to_string(input.capabilities())
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    crate::bindings::bind_agent_in(
        tx,
        proof.tenant_id(),
        receipt.registration,
        &capabilities,
        input.platform(),
        input.architecture(),
    )
    .await?;
    crate::enrollment::store::mark_bound_in(tx, proof.tenant_id(), auth, true).await?;
    proof.enrollment(&auth.device)?;
    audit.registration(receipt.registration);
    let output = wire::RegistrationReceipt {
        wire_version: wire::WIRE_VERSION,
        operation_id: input.operation_id(),
        device_id: receipt.device,
        registration_id: receipt.registration,
        generation: receipt
            .generation
            .try_into()
            .map_err(|_| Error::Unavailable(Failure::Database))?,
        source: wire::ReportSource::AgentBuiltin,
        epoch: receipt.epoch,
        capabilities: input.capabilities().to_vec(),
    };
    crate::operations::save(
        tx,
        operation,
        &serde_json::to_string(&output).expect("closed receipt"),
        audit,
    )
    .await?;
    Ok((output, false))
}

async fn report(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<wire::ReportAck>), AgentError> {
    json_content_type(&headers)?;
    let body = body.map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    bounded(report_inner(&app, &audit, &headers, body)).await
}
async fn report_inner(
    app: &HttpState,
    audit: &RequestAudit,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<wire::ReportAck>), AgentError> {
    let input = parse_report(&body)?;
    let credential = agent_credential(&app.mount, headers)?;
    let (principal, scope) = app
        .devices
        .authorize_report(&credential, InventorySource::AgentBuiltin)
        .await?;
    audit.set_action("agent_report");
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
    let batch = batch(&input)?;
    let fingerprint = batch.fingerprint(&scope).map_err(|_| Error::Malformed)?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
    let control = budget.control();
    let attempt = app.audit_store.write(principal.tenant(), &control,
        (&app.audit_store, &principal, &scope, &input, &batch, audit, &fingerprint),
        |(store, principal, scope, input, batch, audit, fingerprint), tx| Box::pin(async move {
            let (received_at, fresh) = tx.with_connection_context(&mut (*principal, *scope, *input, *batch),
                |(principal, scope, _input, batch), c| Box::pin(async move {crate::bindings::inventory_in(c,principal).await?;crate::collection::agent::accept_in(c,principal,scope,batch).await.map_err(Error::from)})).await?;
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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<wire::ReportStatus>, AgentError> {
    let id =
        Uuid::parse_str(&id).map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    bounded(status_inner(&app, &audit, &headers, id)).await
}
async fn status_inner(
    app: &HttpState,
    audit: &RequestAudit,
    headers: &HeaderMap,
    id: Uuid,
) -> Result<Json<wire::ReportStatus>, AgentError> {
    if id.is_nil() {
        return Err(Error::Malformed.into());
    }
    let credential = agent_credential(&app.mount, headers)?;
    let (principal, scope) = app
        .devices
        .authorize_report(&credential, InventorySource::AgentBuiltin)
        .await?;
    audit.set_action("agent_report_read");
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
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
    let delivery = app.collection.inspect_agent(&report).await?;
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
    Ok(Json(wire::ReportStatus {
        ack: ack(id, received_at),
        observation,
        projection,
    }))
}

fn parse_registration(body: &[u8]) -> Result<wire::RegistrationRequest, AgentError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    let version = value
        .get("wireVersion")
        .and_then(Value::as_u64)
        .ok_or(AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    if version != u64::from(wire::WIRE_VERSION) {
        return Err(AgentError::Wire(wire::ErrorCode::UnsupportedWire));
    }
    let capabilities = value
        .get("capabilities")
        .ok_or(AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    let capabilities: Vec<wire::Capability> = serde_json::from_value(capabilities.clone())
        .map_err(|_| AgentError::Wire(wire::ErrorCode::UnsupportedCapability))?;
    if !wire::supported_capabilities(&capabilities) {
        return Err(AgentError::Wire(wire::ErrorCode::UnsupportedCapability));
    }
    serde_json::from_value(value).map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))
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
pub fn agent_credential(
    mount: &crate::device::ChannelMount,
    headers: &HeaderMap,
) -> Result<VerifiedChannelCredential, AgentError> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(Error::Unauthorized.into());
    }
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::Unauthorized)?;
    let secret = raw.strip_prefix("Bearer ").ok_or(Error::Unauthorized)?;
    if secret.contains(char::is_whitespace) {
        return Err(Error::Unauthorized.into());
    }
    let secret = wire::Secret::parse(secret).map_err(|_| Error::Unauthorized)?;
    Ok(credential(mount, &secret))
}
fn batch(input: &wire::ReportRequest) -> Result<Batch, AgentError> {
    let changes = input
        .values()
        .iter()
        .map(|item| {
            let field = match item.field {
                wire::Field::Model => FieldKey::Model,
                wire::Field::OsVersion => FieldKey::OsVersion,
            };
            let value = match &item.value {
                wire::CollectedValue::Known(value) => {
                    rss_mdm_inventory::CollectedValue::Known(value.clone())
                }
                wire::CollectedValue::Unsupported => rss_mdm_inventory::CollectedValue::Unsupported,
            };
            Ok(Change::upsert(
                Id::new(field.as_str()).map_err(|_| Error::Malformed)?,
                value.encode(field).map_err(|_| Error::Malformed)?,
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
        rss_mdm_inventory::coverage(),
        body,
    )
    .map_err(|_| Error::Malformed.into())
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn registration_digest(input: &wire::RegistrationRequest) -> String {
    let mut hash = Sha256::new();
    let capabilities = serde_json::to_string(input.capabilities()).expect("validated capabilities");
    for value in [
        "rss-mdm.agent.registration.v1",
        &input.operation_id().to_string(),
        &input.enrollment_id().to_string(),
        input.password().expose(),
        input.credential().expose(),
        capabilities.as_str(),
        match input.platform() {
            wire::TaskPlatform::Windows => "windows",
            wire::TaskPlatform::Macos => "macos",
        },
        match input.architecture() {
            wire::TaskArchitecture::X86_64 => "x86_64",
            wire::TaskArchitecture::Aarch64 => "aarch64",
        },
    ] {
        hash.update(value.len().to_be_bytes());
        hash.update(value.as_bytes());
    }
    hex(hash.finalize())
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
    pub mount: crate::device::ChannelMount,
    pub audit_store: Arc<rss_mdm_audit_integration::AuditStore>,
    pub access: std::sync::Arc<crate::database::Store>,
    pub identity: std::sync::Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub credentials: std::sync::Arc<crate::enrollment::credentials::Credentials>,
    pub devices: std::sync::Arc<crate::device::DeviceService>,
    pub collection:
        std::sync::Arc<rss_mdm_inventory_service::collection_service::CollectionService>,
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

fn credential(
    mount: &crate::device::ChannelMount,
    secret: &wire::Secret,
) -> VerifiedChannelCredential {
    let mut hash = Sha256::new();
    hash.update(b"rss-mdm.agent.credential.v1\0");
    hash.update(mount.tenant().to_string().as_bytes());
    hash.update(b"\0");
    hash.update(secret.expose().as_bytes());
    mount.credential(hash.finalize().into())
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
