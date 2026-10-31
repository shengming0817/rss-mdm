//! Script persistence borrows the initiating transaction and never settles it.
use crate::{Error, Result, checked_input, runs::Run, stored};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

pub async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, true).await
}
pub async fn read_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Run> {
    run_in(tx, id, false).await
}
async fn run_in(tx: &mut PgTransaction<'_>, id: Uuid, locked: bool) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row = tx.with_connection(move |c| Box::pin(async move {
        if locked {
            sqlx::query("SELECT id FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
                .bind(&tenant).bind(id).fetch_optional(&mut *c).await?;
        }
        sqlx::query("SELECT * FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2")
            .bind(tenant).bind(id).fetch_optional(c).await
    })).await?.ok_or(Error::NotFound)?;
    Ok(Run {
        id,
        policy_version: row.try_get("policy_version")?,
        resource_id: row.try_get("resource_id")?,
        origin: stored(serde_json::from_value(row.try_get("origin")?))?,
        target: crate::Target {
            device: row.try_get("device")?,
            registration: row.try_get("registration")?,
            generation: row.try_get("generation")?,
        },
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        state: stored(serde_json::from_value(row.try_get("state")?))?,
        source_objects: stored(serde_json::from_value(row.try_get("source_objects")?))?,
        result: row
            .try_get::<Option<Value>, _>("result")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
        invocation: row
            .try_get::<Option<Value>, _>("invocation")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
    })
}

pub async fn save_run(
    service: &crate::Transactions,
    tx: &mut PgTransaction<'_>,
    run: &Run,
) -> Result<()> {
    service.validate_in(tx)?;
    let tenant = tx.tenant_id().to_string();
    let id = run.id;
    let state = checked_input(serde_json::to_value(&run.state))?;
    let result = run
        .result
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Invariant)?;
    let invocation = run
        .invocation
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Invariant)?;
    let (previous, changed) = tx.with_connection(move |c| Box::pin(async move {
        let previous: Value = sqlx::query_scalar("SELECT state FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
            .bind(&tenant).bind(id).fetch_one(&mut *c).await?;
        let changed = sqlx::query("UPDATE mdm_script.runs SET state=$3,result=$4,invocation=$5 WHERE tenant_id=$1::uuid AND id=$2 AND (state IS DISTINCT FROM $3 OR result IS DISTINCT FROM $4 OR invocation IS DISTINCT FROM $5)")
            .bind(tenant).bind(id).bind(state).bind(result).bind(invocation).execute(c).await?.rows_affected() > 0;
        Ok((previous, changed))
    })).await?;
    if !changed {
        return Ok(());
    }
    crate::wake::run_in(&service.reconcile_messaging, tx, run.id).await?;
    use rss_mdm_task_state::{Cancellation, Execution};
    let terminal = match run.state.execution {
        Execution::Succeeded => Some("succeeded"),
        Execution::Failed => Some("failed"),
        _ if run.state.cancellation == Cancellation::Confirmed => Some("cancelled"),
        _ => None,
    };
    if let Some(status) = terminal {
        let cancelled = previous.get("cancellation").and_then(Value::as_str) == Some("confirmed");
        if previous.get("execution").and_then(Value::as_str) != Some(status)
            && !(status == "cancelled" && cancelled)
        {
            use rss_mdm_webhook_service::{events, model::*};
            events::emit_in(
                tx,
                Event {
                    event_id: events::identity(run.id, &format!("terminal:{status}")),
                    event_type: EventType::PolicyTerminal,
                    version: 1,
                    occurred_at: now(tx).await?,
                    tenant_id: stored(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                    device_id: run.target.device.clone(),
                    data: EventData::Policy {
                        run_id: run.id,
                        policy_version: run.policy_version,
                        registration_id: run.target.registration,
                        generation: run.target.generation,
                        status: status.into(),
                    },
                },
            )
            .await
            .map_err(rss_transactional_messaging_postgres::PgError::from)?;
        }
    }
    Ok(())
}

/// The caller holds the device fence across this check and admission. Unknown is
/// intentionally independent of Policy, version, registration, deadline and cancellation.
pub async fn pending_in(
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
    version: Uuid,
    target: &crate::Target,
    resource_id: &str,
    now: i64,
) -> Result<(bool, Option<i64>)> {
    let tenant = tx.tenant_id().to_string();
    let target = target.clone();
    let resource = resource_id.to_owned();
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM mdm_script.runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND ((r.resource_id=$3 AND (r.state->>'execution'='unknown' OR (r.state->>'execution'='running' AND r.deadline<=$7))) OR (v.policy=$4 AND r.registration=$6 AND r.state->>'cancellation'<>'confirmed' AND (r.state->>'execution'='running' OR (r.state->>'execution'='not_started' AND r.deadline>$7))))), (SELECT max(created_at) FROM mdm_script.runs WHERE tenant_id=$1::uuid AND device=$2 AND policy_version=$5 AND registration=$6)")
            .bind(tenant).bind(target.device).bind(resource).bind(policy).bind(version)
            .bind(target.registration).bind(now).fetch_one(c).await
    })).await?)
}

pub async fn active_count_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    now: i64,
) -> std::result::Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM mdm_script.runs WHERE tenant_id=$1::uuid AND device=$2 AND state->>'execution' IN('not_started','running') AND state->>'cancellation'<>'confirmed' AND deadline>$3")
        .bind(tenant.to_string()).bind(device).bind(now).fetch_one(c).await
}
pub async fn owned_ids_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    ids: &[Uuid],
) -> std::result::Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT id FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=ANY($2)")
        .bind(tenant.to_string())
        .bind(ids)
        .fetch_all(c)
        .await
}

/// All self-service owners use this same request lock before checking saved receipts.
pub async fn lock_request(tx: &mut PgTransaction<'_>, actor: &str, id: Uuid) -> Result<()> {
    let key = format!("{}:action-request:{actor}:{id}", tx.tenant_id());
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2465))")
                .bind(key)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub async fn replay(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: &[u8],
) -> Result<Option<Value>> {
    lock_request(tx, actor, id).await?;
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let row = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("SELECT fingerprint,response FROM mdm_script.receipts WHERE tenant_id=$1::uuid AND actor=$2 AND id=$3")
            .bind(tenant).bind(actor).bind(id).fetch_optional(c).await
    })).await?;
    row.map(|row| {
        if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
            return Err(Error::Conflict.into());
        }
        Ok(row.try_get("response")?)
    })
    .transpose()
}
pub async fn receipt(
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: Vec<u8>,
    response: &Value,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let response = response.clone();
    tx.with_connection(move |c| Box::pin(async move {
        sqlx::query("INSERT INTO mdm_script.receipts(tenant_id,actor,id,fingerprint,response) VALUES($1::uuid,$2,$3,$4,$5)")
            .bind(tenant).bind(actor).bind(id).bind(fingerprint).bind(response).execute(c).await?;
        Ok(())
    })).await?;
    Ok(())
}
pub async fn lock_device(tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let devices = vec![device.to_owned()];
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(
                rss_mdm_registration_service::lifecycle::lock_devices_in(c, &tenant, &devices)
                    .await,
            )
        })
    })
    .await??;
    Ok(())
}
pub async fn now(tx: &mut PgTransaction<'_>) -> Result<i64> {
    Ok(tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(c)
                    .await
            })
        })
        .await?)
}
pub async fn authorized(
    tx: &mut PgTransaction<'_>,
    proof: &crate::authorization::context::AuthorizedPrincipal,
    device: &str,
    permission: crate::authorization::Permission,
) -> Result<crate::authorization::Snapshot> {
    let snapshot = current(tx, proof).await?;
    snapshot.require(proof, permission, Some(device))?;
    Ok(snapshot)
}
pub async fn current(
    tx: &mut PgTransaction<'_>,
    proof: &crate::authorization::context::AuthorizedPrincipal,
) -> Result<crate::authorization::Snapshot> {
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    let snapshot = tx
        .with_connection(move |c| {
            Box::pin(async move {
                crate::authorization::lock_shared_on(c, &tenant, &instance)
                    .await
                    .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(crate::authorization::snapshot_on(c, &tenant, &instance).await)
            })
        })
        .await??;
    Ok(snapshot)
}

/// A late recovery worker must not create a window for another Policy to start.
pub async fn unknown_conflict_in(tx: &mut PgTransaction<'_>, run: &Run) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let device = run.target.device.clone();
    let resource = run.resource_id.clone();
    let id = run.id;
    Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_script.runs WHERE tenant_id=$1::uuid AND device=$2 AND resource_id=$3 AND id<>$4 AND (state->>'execution'='unknown' OR (state->>'execution'='running' AND deadline<=floor(extract(epoch FROM clock_timestamp())))))").bind(tenant).bind(device).bind(resource).bind(id).fetch_one(c).await})).await?)
}
