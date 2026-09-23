//! Strict Agent V1 HTTP adapter. Wire values never carry tenant, device or generation authority.

use crate::{
    AccessStore, Error, Failure,
    access_store::{Actor, Operation, db},
    api::{App, authenticate},
    audit::Audit,
    device::{BindRegistration, VerifiedChannelCredential, store::bind_in},
    enrollment::Password,
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
use rss_mdm_inventory::{FieldKey, ReportSource as InventorySource};
use rss_observation::{Batch, Body, Change, Id};
use rss_request_context::TenantId;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{future::Future, sync::Arc, time::Duration};
use uuid::Uuid;
const MAX_PENDING_REPORTS_PER_REGISTRATION: i64 = 32;

pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/registrations", post(register))
        .route("/reports", post(report))
        .route("/reports/{id}", get(status))
}

#[derive(Clone)]
enum AgentError {
    Wire(wire::ErrorCode),
    App(Error),
}
impl From<Error> for AgentError {
    fn from(value: Error) -> Self {
        Self::App(value)
    }
}
impl IntoResponse for AgentError {
    fn into_response(self) -> Response {
        let (status, code, app_error) = match self {
            Self::Wire(code) => (status_for(code), code, None),
            Self::App(error) => {
                let code = match error {
                    Error::Malformed
                    | Error::CertificateRequest
                    | Error::ConfigurationTargetLimit => wire::ErrorCode::MalformedRequest,
                    Error::Conflict | Error::Plan(_) => wire::ErrorCode::OperationConflict,
                    Error::CommitUnknown => wire::ErrorCode::OperationUnknown,
                    Error::Unauthorized | Error::Forbidden => wire::ErrorCode::InvalidIdentity,
                    Error::NotFound | Error::ManagementNotFound(_) => {
                        wire::ErrorCode::ReportNotFound
                    }
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
        wire::ErrorCode::ReportNotFound => StatusCode::NOT_FOUND,
        wire::ErrorCode::OperationConflict => StatusCode::CONFLICT,
        wire::ErrorCode::OperationUnknown | wire::ErrorCode::ServiceUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

async fn bounded<T>(
    _app: &Arc<App>,
    work: impl Future<Output = Result<T, AgentError>>,
) -> Result<T, AgentError> {
    tokio::time::timeout(Duration::from_secs(8), work)
        .await
        .map_err(|_| AgentError::App(Error::Unavailable(Failure::RequestDeadline)))?
}

pub(crate) fn ingress_error(code: wire::ErrorCode) -> Response {
    AgentError::Wire(code).into_response()
}

async fn register(
    State(app): State<Arc<App>>,
    Extension(audit): Extension<Audit>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<wire::RegistrationReceipt>), AgentError> {
    json_content_type(&headers)?;
    let body = body.map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    bounded(&app, register_inner(&app, &audit, body)).await
}
async fn register_inner(
    app: &App,
    audit: &Audit,
    body: Bytes,
) -> Result<(StatusCode, Json<wire::RegistrationReceipt>), AgentError> {
    let input = parse_registration(&body)?;
    audit.set_action("agent_registration");
    audit.operation(input.operation_id(), "agent_registration");
    let password = Password::new(input.password().expose().to_owned())?;
    let auth = app
        .access
        .enrollment_authorization(
            &app.identity.tenant.to_string(),
            input.enrollment_id(),
            &password,
        )
        .await?;
    if auth.source != InventorySource::AgentBuiltin {
        return Err(Error::Unauthorized.into());
    }
    let proof = authenticate(app, app.credentials.get(auth.credential_ref)?).await?;
    if proof.principal_id() != auth.actor || proof.instance_id() != auth.instance {
        return Err(Error::Unauthorized.into());
    }
    proof.enrollment(&auth.device)?;
    audit.identify(&proof);
    audit.target(&auth.device);
    let credential = VerifiedChannelCredential::agent(
        TenantId::parse(proof.tenant_id()).map_err(|_| Error::Unauthorized)?,
        input.credential(),
    );
    let digest = registration_digest(&input);
    let operation = Operation {
        actor: Actor {
            tenant: proof.tenant_id(),
            subject: proof.principal_id(),
            instance: proof.instance_id(),
        },
        key: input.operation_id(),
        digest: &digest,
    };
    let mut tx = app.access.begin(proof.tenant_id()).await?;
    if let Some(old) = AccessStore::replay(&mut tx, &operation).await? {
        let receipt: wire::RegistrationReceipt =
            serde_json::from_str(&old).map_err(|_| Error::Unavailable(Failure::AccessStore))?;
        if app
            .access
            .active_registration(&mut tx, proof.tenant_id(), auth.id)
            .await?
            != receipt.registration_id
        {
            return Err(Error::Conflict.into());
        }
        tx.rollback().await.map_err(db)?;
        proof.enrollment(&auth.device)?;
        return Ok((StatusCode::OK, Json(receipt)));
    }
    let receipt = bind_in(
        &mut tx,
        &proof,
        &credential,
        &BindRegistration {
            operation_id: input.operation_id(),
            request_id: input.enrollment_id(),
            expected_generation: auth.expected_generation,
            source: InventorySource::AgentBuiltin,
        },
        auth.device.clone(),
        [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
    )
    .await?;
    sqlx::query("INSERT INTO mdm_access.agent_bindings(tenant_id,registration,wire_version,capabilities) VALUES($1::uuid,$2::uuid,1,'[\"inventory.basic.v1\"]')")
        .bind(proof.tenant_id()).bind(receipt.registration.to_string()).execute(&mut *tx).await.map_err(db)?;
    let changed = sqlx::query("UPDATE mdm_access.requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2::uuid AND state='pending' AND source='agent.builtin' AND password_version=$3 AND credential_ref=$4::uuid AND expires_at>clock_timestamp()")
        .bind(proof.tenant_id()).bind(auth.id.to_string()).bind(auth.version).bind(auth.credential_ref.to_string()).execute(&mut *tx).await.map_err(db)?;
    if changed.rows_affected() != 1 {
        return Err(Error::Unauthorized.into());
    }
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
            .map_err(|_| Error::Unavailable(Failure::AccessStore))?,
        source: wire::ReportSource::AgentBuiltin,
        epoch: receipt.epoch,
        capabilities: vec![wire::Capability::InventoryBasicV1],
    };
    app.access
        .finish_status(
            tx,
            &operation,
            &serde_json::to_string(&output).expect("closed receipt"),
            audit,
            Some(auth.id),
            201,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(output)))
}

async fn report(
    State(app): State<Arc<App>>,
    Extension(audit): Extension<Audit>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<wire::ReportAck>), AgentError> {
    json_content_type(&headers)?;
    let body = body.map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    bounded(&app, report_inner(&app, &audit, &headers, body)).await
}
async fn report_inner(
    app: &App,
    audit: &Audit,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<wire::ReportAck>), AgentError> {
    let input = parse_report(&body)?;
    let credential = agent_credential(app, headers)?;
    let (principal, scope) = app
        .devices
        .authorize_report(&credential, InventorySource::AgentBuiltin)
        .await?;
    audit.set_action("agent_report");
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target(principal.device());
    let batch = batch(&input)?;
    let digest = fingerprint(&batch, &scope)?;
    let mut tx = app.access.begin(&principal.tenant().to_string()).await?;
    let live_scope =
        crate::collection::revalidate_source(&mut tx, &principal, InventorySource::AgentBuiltin)
            .await?;
    if live_scope != scope {
        return Err(Error::Unauthorized.into());
    }
    // V1 report ids are tenant-global. This lock covers the absent-row case across registrations;
    // revalidate_source already holds the channel lock that serializes capacity and retention.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2467))")
        .bind(format!("{}:{}", principal.tenant(), input.report_id()))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if let Some(row) = sqlx::query("SELECT registration::text,source,epoch::text,digest,sealed_at FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2::uuid FOR SHARE")
        .bind(principal.tenant().to_string()).bind(input.report_id().to_string()).fetch_optional(&mut *tx).await.map_err(db)? {
        if row.try_get::<String, _>("registration").map_err(db)? != principal.registration().to_string()
            || row.try_get::<String, _>("source").map_err(db)? != InventorySource::AgentBuiltin.as_str()
            || row.try_get::<String, _>("epoch").map_err(db)? != scope.epoch().as_str()
            || row.try_get::<String, _>("digest").map_err(db)? != digest {
            return Err(Error::Conflict.into());
        }
        let ack = ack(input.report_id(), row.try_get("sealed_at").map_err(db)?);
        tx.rollback().await.map_err(db)?;
        return Ok((StatusCode::ACCEPTED, Json(ack)));
    }
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND registration=$2::uuid AND source='agent.builtin' AND epoch=$3::uuid AND delivery_pending")
        .bind(principal.tenant().to_string()).bind(principal.registration().to_string()).bind(scope.epoch().as_str()).fetch_one(&mut *tx).await.map_err(db)?;
    if pending >= MAX_PENDING_REPORTS_PER_REGISTRATION {
        return Err(Error::Unavailable(Failure::Capacity).into());
    }
    let _: i64 = sqlx::query_scalar("SELECT mdm_access.prune_agent_collections($1::uuid,$2::uuid)")
        .bind(principal.registration().to_string())
        .bind(scope.epoch().as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    let received_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
    let result = match input.body() {
        wire::ReportBody::Snapshot(_) => "snapshot",
        wire::ReportBody::Partial(_) => "partial",
        wire::ReportBody::Failed { .. } => "failed",
    };
    let attempts = crate::collection::Attempts::agent(input.body(), received_at)?;
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending) VALUES($1::uuid,$4::uuid,$2::uuid,'agent.builtin',$3::uuid,$6,$5,NULL,NULL,NULL,NULL,$9,$11,$10,'complete',$7,$8,$9,true)")
        .bind(principal.tenant().to_string()).bind(principal.registration().to_string()).bind(scope.epoch().as_str()).bind(input.report_id().to_string())
        .bind(i64::try_from(input.sequence()).map_err(|_| Error::Malformed)?).bind(scope.encode().map_err(|_| Error::Malformed)?)
        .bind(batch.encode()).bind(&digest).bind(received_at).bind(result)
        .bind(serde_json::to_string(&attempts).expect("closed attempts")).execute(&mut *tx).await.map_err(db)?;
    app.access
        .commit_audited_status(tx, audit, None, 202)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ack(input.report_id(), received_at)),
    ))
}

async fn status(
    State(app): State<Arc<App>>,
    Extension(audit): Extension<Audit>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<wire::ReportStatus>, AgentError> {
    let id =
        Uuid::parse_str(&id).map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    bounded(&app, status_inner(&app, &audit, &headers, id)).await
}
async fn status_inner(
    app: &App,
    audit: &Audit,
    headers: &HeaderMap,
    id: Uuid,
) -> Result<Json<wire::ReportStatus>, AgentError> {
    if id.is_nil() {
        return Err(Error::Malformed.into());
    }
    let credential = agent_credential(app, headers)?;
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
        crate::collection::revalidate_source(&mut tx, &principal, InventorySource::AgentBuiltin)
            .await?;
    if live_scope != scope {
        return Err(Error::Unauthorized.into());
    }
    let (report, received_at) = AccessStore::agent_report_in(&mut tx, &scope, id)
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
        crate::inventory_runtime::ProjectionStatus::Projected => wire::ProjectionStatus::Applied,
        crate::inventory_runtime::ProjectionStatus::NotApplicable => {
            wire::ProjectionStatus::NotApplicable
        }
        crate::inventory_runtime::ProjectionStatus::Pending
        | crate::inventory_runtime::ProjectionStatus::PendingReceipt => {
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
    if capabilities != &serde_json::json!(["inventory.basic.v1"]) {
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
fn agent_credential(
    app: &App,
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
    Ok(VerifiedChannelCredential::agent(
        TenantId::parse(&app.identity.tenant.to_string()).map_err(|_| Error::Unauthorized)?,
        &secret,
    ))
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
fn fingerprint(batch: &Batch, scope: &rss_observation::Scope) -> Result<String, AgentError> {
    Ok(hex(batch
        .fingerprint(scope)
        .map_err(|_| Error::Malformed)?))
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn registration_digest(input: &wire::RegistrationRequest) -> String {
    let mut hash = Sha256::new();
    for value in [
        "rss-mdm.agent.registration.v1",
        &input.operation_id().to_string(),
        &input.enrollment_id().to_string(),
        input.password().expose(),
        input.credential().expose(),
        "inventory.basic.v1",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_discriminators_distinguish_absent_from_unsupported() {
        let error =
            parse_report(br#"{"reportId":"00000000-0000-0000-0000-000000000001"}"#).unwrap_err();
        assert!(matches!(
            error,
            AgentError::Wire(wire::ErrorCode::MalformedRequest)
        ));
        let error = parse_report(br#"{"wireVersion":2}"#).unwrap_err();
        assert!(matches!(
            error,
            AgentError::Wire(wire::ErrorCode::UnsupportedWire)
        ));
    }
}
