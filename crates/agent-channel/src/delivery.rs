//! Agent task delivery owns protocol identities, signed bytes and request replay.
//! Business participants borrow the original RSS transaction; only this request settles it.
use crate::{Error, Failure, database::db};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_audit_integration::{AuditStore, Fact, RequestAudit};
use rss_mdm_registration_service::DevicePrincipal;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;

pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
pub struct EventEffects {
    pub start: Option<wire::TaskPayload>,
    pub cancelled: bool,
    pub credentials: Vec<wire::CredentialReceipt>,
    pub fact: Fact,
}
/// Current business admission and result handling, with no transport or transaction owner.
pub trait Tasks: Send + Sync {
    fn prepare<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
    ) -> Pending<'a, ()>;
    fn offer<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        input: &'a wire::TaskClaimRequest,
        attempt: Uuid,
        audit: &'a RequestAudit,
    ) -> Pending<'a, Option<(wire::TaskPayload, Fact, i64)>>;
    fn replay_offer<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        signed: &'a wire::SignedTask,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    fn replay_event<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        task: Uuid,
        input: &'a wire::TaskEventRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, ()>;
    fn event<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        task: Uuid,
        input: &'a wire::TaskEventRequest,
        audit: &'a RequestAudit,
    ) -> Pending<'a, EventEffects>;
    fn cancellations<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        registration: Uuid,
        after: Option<Uuid>,
    ) -> Pending<'a, Vec<wire::TaskCancellation>>;
    fn content<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        p: &'a DevicePrincipal,
        task: Uuid,
        attempt: Uuid,
        key: Option<&'a str>,
        audit: &'a RequestAudit,
    ) -> Pending<'a, rss_mdm_resource::Artifact>;
}
pub struct Delivery {
    pub runtime: Arc<PgRuntime>,
    pub tenant: TenantId,
    pub audit: Arc<AuditStore>,
    pub signing: Arc<rss_mdm_task_trust::Signing>,
    pub tasks: Arc<dyn Tasks>,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
}
impl Delivery {
    async fn run<C: Send, R: Send, F>(
        &self,
        audit: &RequestAudit,
        context: C,
        operation: F,
    ) -> Result<R, Error>
    where
        F: for<'a> FnOnce(&'a mut C, &'a mut PgTransaction<'_>) -> Pending<'a, R> + Send,
    {
        let failure = Mutex::new(None);
        let attempt = self
            .runtime
            .local_tx_with_context(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    Duration::from_secs(6),
                ),
                (context, Some(operation), &failure, &self.audit, audit),
                |(context, operation, failure, store, audit), tx| {
                    Box::pin(async move {
                        store
                            .bind_in(tx)
                            .await
                            .map_err(|e| rejection(e.into(), failure))?;
                        match operation.take().expect("one request")(context, tx).await {
                            Ok(v) => {
                                audit.mark_commit_started();
                                Ok(v)
                            }
                            Err(e) => Err(rejection(e, failure)),
                        }
                    })
                },
            )
            .await;
        attempt.fold(
            |v| {
                audit.mark_committed();
                Ok(v)
            },
            |_| Err(Error::Unavailable(Failure::Database)),
            |_| {
                audit.mark_rolled_back();
                Err(failure
                    .into_inner()
                    .expect("request rejection")
                    .unwrap_or(Error::Unavailable(Failure::Database)))
            },
            |_| {
                audit.mark_rollback_failed();
                Err(Error::RollbackFailed)
            },
            |_| Err(Error::CommitUnknown),
            |_| Err(Error::Unavailable(Failure::Database)),
        )
    }
    pub async fn claim(
        &self,
        p: &DevicePrincipal,
        input: &wire::TaskClaimRequest,
        audit: &RequestAudit,
    ) -> Result<wire::TaskClaimResponse, Error> {
        self.run(audit, (self, p, input, audit), |ctx, tx| {
            Box::pin(async move {
                let (s, p, input, audit) = *ctx;
                s.tasks.prepare(tx, p).await?;
                let principal = p.clone();
                let claim = input.clone();
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(async {
                            crate::Bindings
                                .update_context(
                                    c,
                                    principal.tenant().to_string(),
                                    principal.registration(),
                                    claim.execution_context(),
                                )
                                .await?;
                            crate::Bindings
                                .announce(
                                    c,
                                    principal.tenant().to_string(),
                                    principal.registration(),
                                    &claim,
                                )
                                .await?;
                            rss_mdm_registration_service::device::store::record_communication_in(
                                c, &principal,
                            )
                            .await?;
                            Ok::<_, Error>(())
                        }
                        .await)
                    })
                })
                .await
                .map_err(storage)??;
                let hash = fingerprint(input)?;
                if let Some(value) =
                    replay(tx, p.registration(), input.operation_id(), &hash).await?
                {
                    let response: wire::TaskClaimResponse = serde_json::from_value(value)
                        .map_err(|_| Error::Unavailable(Failure::Protocol))?;
                    if let Some(signed) = response.task() {
                        s.tasks.replay_offer(tx, p, signed, audit).await?;
                    }
                    audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                    return Ok(response);
                }
                let attempt = Uuid::new_v4();
                let offer = s.tasks.offer(tx, p, input, attempt, audit).await?;
                let (signed, fact) = if let Some((payload, fact, deadline)) = offer {
                    if payload.attempt_id() != attempt {
                        return Err(Error::Conflict);
                    }
                    let signed = s.sign(tx, p, payload).await?;
                    persist_offer(tx, p, &signed, deadline).await?;
                    (Some(signed), Some(fact))
                } else {
                    (None, None)
                };
                let after = cancellation_after(tx, p.registration()).await?;
                let cancellations = s.tasks.cancellations(tx, p.registration(), after).await?;
                let next = cancellations.last().map(|c| c.task_id());
                save_cancellation_after(tx, p.registration(), next).await?;
                let response = wire::TaskClaimResponse::new(signed, cancellations)
                    .map_err(|_| Error::Malformed)?;
                if let Some(fact) = fact {
                    receipt(tx, p.registration(), input.operation_id(), hash, &response).await?;
                    s.audit.append_in(tx, &fact).await?;
                }
                Ok(response)
            })
        })
        .await
    }
    pub async fn event(
        &self,
        p: &DevicePrincipal,
        task: Uuid,
        input: &wire::TaskEventRequest,
        audit: &RequestAudit,
    ) -> Result<wire::TaskEventAck, Error> {
        self.run(audit, (self, p, task, input, audit), |ctx, tx| {
            Box::pin(async move {
                let (s, p, task, input, audit) = *ctx;
                s.tasks.prepare(tx, p).await?;
                if matches!(
                    input.event(),
                    wire::TaskEvent::Start | wire::TaskEvent::Received
                ) {
                    let principal = p.clone();
                    let context = input.execution_context().clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::Bindings
                                .update_context(
                                    c,
                                    principal.tenant().to_string(),
                                    principal.registration(),
                                    &context,
                                )
                                .await)
                        })
                    })
                    .await
                    .map_err(storage)??;
                }
                let hash = fingerprint(&(task, input))?;
                if let Some(value) =
                    replay(tx, p.registration(), input.operation_id(), &hash).await?
                {
                    s.tasks.replay_event(tx, p, task, input, audit).await?;
                    audit.management_result(rss_mdm_audit_integration::ManagementResult::Replayed);
                    return serde_json::from_value(value)
                        .map_err(|_| Error::Unavailable(Failure::Protocol));
                }
                let effect = s.tasks.event(tx, p, task, input, audit).await?;
                let permit = if let Some(expected) = effect.start {
                    let tenant = tx.tenant_id().to_string();
                    let attempt = input.attempt_id();
                    let mut original = tx
                        .with_connection(move |c| {
                            Box::pin(async move { Ok(payload(c, tenant, task, attempt).await) })
                        })
                        .await
                        .map_err(storage)??;
                    start_permit(&mut original, expected.expires_at());
                    if original != expected {
                        return Err(Error::Forbidden);
                    }
                    let signed = s.sign(tx, p, expected).await?;
                    persist_permit(tx, task, input.attempt_id(), &signed).await?;
                    Some(signed)
                } else {
                    None
                };
                let response = wire::TaskEventAck::new(permit, effect.cancelled)
                    .with_credentials(effect.credentials);
                receipt(tx, p.registration(), input.operation_id(), hash, &response).await?;
                s.audit.append_in(tx, &effect.fact).await?;
                Ok(response)
            })
        })
        .await
    }
    async fn sign(
        &self,
        tx: &mut PgTransaction<'_>,
        p: &DevicePrincipal,
        payload: wire::TaskPayload,
    ) -> Result<wire::SignedTask, Error> {
        let p = p.clone();
        let signing = self.signing.clone();
        tx.with_connection(move |c| {
            Box::pin(async move { Ok(signing.sign_task_on(c, &p, payload).await) })
        })
        .await
        .map_err(storage)?
        .map_err(Into::into)
    }
    pub async fn download(
        &self,
        p: &DevicePrincipal,
        task: Uuid,
        attempt: Uuid,
        key: Option<&str>,
        audit: &RequestAudit,
    ) -> Result<rss_mdm_content_service::Verified, Error> {
        let artifact = self.authorize_content(p, task, attempt, key, audit).await?;
        let verified = self
            .content
            .as_ref()
            .ok_or(Error::Unsupported)?
            .verify(&artifact)
            .await?;
        let current = self.authorize_content(p, task, attempt, key, audit).await?;
        if !verified.matches(&current) {
            return Err(Error::Conflict);
        }
        Ok(verified)
    }
    async fn authorize_content(
        &self,
        p: &DevicePrincipal,
        task: Uuid,
        attempt: Uuid,
        key: Option<&str>,
        audit: &RequestAudit,
    ) -> Result<rss_mdm_resource::Artifact, Error> {
        let failure = Mutex::new(None);
        self.runtime
            .local_tx_with_context(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    Duration::from_secs(6),
                ),
                (self, p, task, attempt, key, audit, &failure),
                |ctx, tx| {
                    Box::pin(async move {
                        let (s, p, task, attempt, key, audit, failure) = *ctx;
                        s.tasks
                            .content(tx, p, task, attempt, key, audit)
                            .await
                            .map_err(|e| rejection(e, failure))
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::Database)),
                |_| {
                    Err(failure
                        .into_inner()
                        .expect("content rejection")
                        .unwrap_or(Error::Unavailable(Failure::Database)))
                },
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::Database)),
            )
    }
}
fn rejection(e: Error, failure: &Mutex<Option<Error>>) -> PgError {
    *failure.lock().expect("request rejection") = Some(e);
    sqlx::Error::Protocol("Agent request rejected".into()).into()
}
fn storage(e: PgError) -> Error {
    e.into()
}
fn fingerprint(value: &impl serde::Serialize) -> Result<Vec<u8>, Error> {
    Ok(Sha256::digest(serde_json::to_vec(value).map_err(|_| Error::Malformed)?).to_vec())
}
/// Original protocol evidence. Reading it grants no execution or disclosure authority.
pub async fn payload(
    c: &mut PgConnection,
    tenant: String,
    run: Uuid,
    attempt: Uuid,
) -> Result<wire::TaskPayload, Error> {
    let value:serde_json::Value=sqlx::query_scalar("SELECT coalesce(permit,offer) FROM mdm_agent.task_attempts WHERE tenant_id=$1::uuid AND run=$2 AND id=$3").bind(tenant).bind(run).bind(attempt).fetch_optional(c).await.map_err(db)?.ok_or(Error::Conflict)?;
    let signed: wire::SignedTask =
        serde_json::from_value(value).map_err(|_| Error::Unavailable(Failure::Protocol))?;
    if signed.payload.task_id() != run || signed.payload.attempt_id() != attempt {
        return Err(Error::Conflict);
    }
    Ok(signed.payload)
}
async fn replay(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    operation: Uuid,
    hash: &[u8],
) -> Result<Option<serde_json::Value>, Error> {
    let tenant = tx.tenant_id().to_string();
    let hash = hash.to_vec();
    tx.with_connection(move |c|Box::pin(async move {Ok(async {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3116))").bind(format!("{tenant}:{registration}:{operation}")).execute(&mut *c).await.map_err(db)?;
        let row=sqlx::query("SELECT fingerprint,response FROM mdm_agent.task_receipts WHERE tenant_id=$1::uuid AND registration=$2 AND id=$3").bind(tenant).bind(registration).bind(operation).fetch_optional(c).await.map_err(db)?;
        row.map(|row|{if row.try_get::<Vec<u8>,_>("fingerprint").map_err(db)?!=hash {return Err(Error::Conflict);} row.try_get("response").map_err(db)}).transpose()
    }.await)})).await.map_err(storage)?
}
async fn receipt(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    operation: Uuid,
    hash: Vec<u8>,
    response: &impl serde::Serialize,
) -> Result<(), Error> {
    let tenant = tx.tenant_id().to_string();
    let value = serde_json::to_value(response).map_err(|_| Error::Malformed)?;
    tx.with_connection(move |c|Box::pin(async move {sqlx::query("INSERT INTO mdm_agent.task_receipts(tenant_id,registration,id,fingerprint,response) VALUES($1::uuid,$2,$3,$4,$5)").bind(tenant).bind(registration).bind(operation).bind(hash).bind(value).execute(c).await?;Ok(())})).await.map_err(storage)
}
async fn persist_offer(
    tx: &mut PgTransaction<'_>,
    p: &DevicePrincipal,
    signed: &wire::SignedTask,
    deadline: i64,
) -> Result<(), Error> {
    let tenant = tx.tenant_id().to_string();
    let registration = p.registration();
    let run = signed.payload.task_id();
    let attempt = signed.payload.attempt_id();
    let value = serde_json::to_value(signed).map_err(|_| Error::Malformed)?;
    tx.with_connection(move |c|Box::pin(async move {sqlx::query("INSERT INTO mdm_agent.task_attempts(tenant_id,id,run,registration,claimed_at,offer,deadline) VALUES($1::uuid,$2,$3,$4,floor(extract(epoch FROM clock_timestamp()))::bigint,$5,$6)").bind(tenant).bind(attempt).bind(run).bind(registration).bind(value).bind(deadline).execute(c).await?;Ok(())})).await.map_err(storage)
}
async fn persist_permit(
    tx: &mut PgTransaction<'_>,
    run: Uuid,
    attempt: Uuid,
    signed: &wire::SignedTask,
) -> Result<(), Error> {
    let tenant = tx.tenant_id().to_string();
    let value = serde_json::to_value(signed).map_err(|_| Error::Malformed)?;
    let n=tx.with_connection(move |c|Box::pin(async move {Ok(sqlx::query("UPDATE mdm_agent.task_attempts SET permit=$4 WHERE tenant_id=$1::uuid AND run=$2 AND id=$3 AND permit IS NULL").bind(tenant).bind(run).bind(attempt).bind(value).execute(c).await?.rows_affected())})).await.map_err(storage)?;
    if n != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn cancellation_after(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Option<Uuid>, Error> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_agent.task_polls(tenant_id,registration) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(registration).execute(&mut *c).await?;
        sqlx::query_scalar("SELECT cancellation_after FROM mdm_agent.task_polls WHERE tenant_id=$1::uuid AND registration=$2 FOR UPDATE").bind(tenant).bind(registration).fetch_one(c).await
    })).await.map_err(storage)
}
async fn save_cancellation_after(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    after: Option<Uuid>,
) -> Result<(), Error> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move{sqlx::query("UPDATE mdm_agent.task_polls SET cancellation_after=$3 WHERE tenant_id=$1::uuid AND registration=$2").bind(tenant).bind(registration).bind(after).execute(c).await?;Ok(())})).await.map_err(storage)
}
fn start_permit(payload: &mut wire::TaskPayload, expiry: i64) {
    macro_rules! permit {
        ($v:expr) => {{
            $v.permit = wire::TaskPermit::Start;
            $v.expires_at = expiry;
        }};
    }
    match payload {
        wire::TaskPayload::DeviceAccess(v) => permit!(v),
        wire::TaskPayload::Credential(v) => permit!(v),
        wire::TaskPayload::Collection(v) => permit!(v),
        wire::TaskPayload::Script(v) => permit!(v),
        wire::TaskPayload::Software(v) => permit!(v),
        wire::TaskPayload::Enrollment(v) => permit!(v),
        wire::TaskPayload::Unmanage(v) => permit!(v),
    }
}

/// Protocol polling advances once across App's bounded composition of concrete owners.
pub async fn offer_after_in(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
) -> Result<Option<(i64, Uuid)>, Error> {
    let tenant = tx.tenant_id().to_string();
    let (at,id) = tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_agent.task_polls(tenant_id,registration) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(registration).execute(&mut *c).await?;
        sqlx::query_as::<_,(Option<i64>,Option<Uuid>)>("SELECT offer_after_at,offer_after_id FROM mdm_agent.task_polls WHERE tenant_id=$1::uuid AND registration=$2 FOR UPDATE").bind(tenant).bind(registration).fetch_one(c).await
    })).await.map_err(storage)?;
    match (at, id) {
        (None, None) => Ok(None),
        (Some(at), Some(id)) => Ok(Some((at, id))),
        _ => Err(Error::Unavailable(Failure::Protocol)),
    }
}
pub async fn offer_through_in(
    tx: &mut PgTransaction<'_>,
    registration: Uuid,
    after: Option<(i64, Uuid)>,
) -> Result<(), Error> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("UPDATE mdm_agent.task_polls SET offer_after_at=$3,offer_after_id=$4 WHERE tenant_id=$1::uuid AND registration=$2")
            .bind(tenant).bind(registration).bind(after.map(|v|v.0)).bind(after.map(|v|v.1)).execute(c).await?;Ok(())
    })).await.map_err(storage)
}
