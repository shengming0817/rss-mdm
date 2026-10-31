//! Collection task persistence borrows the initiating transaction and never settles it.
use super::{model::AgentRun, service::Transactions};
use crate::{
    Error,
    transaction::{Result, checked_input, stored},
};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;
pub async fn native_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<super::model::NativeRun> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT * FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2 AND channel='mdm' FOR UPDATE").bind(tenant).bind(id).fetch_optional(c).await})).await?.ok_or(Error::NotFound)?;
    Ok(super::model::NativeRun {
        id,
        policy_version: row.try_get("policy_version")?,
        origin: stored(serde_json::from_value(row.try_get("origin")?))?,
        target: super::model::Target {
            device: row.try_get("device")?,
            registration: row.try_get("registration")?,
            generation: row.try_get("generation")?,
        },
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        delivery: stored(serde_json::from_value(serde_json::json!(
            row.try_get::<String, _>("native_delivery")?
        )))?,
        collection_run: row.try_get("collection_run")?,
        started_at: row.try_get("started_at")?,
        source_objects: stored(serde_json::from_value(row.try_get("source_objects")?))?,
    })
}
pub async fn save_native(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    run: &super::model::NativeRun,
) -> Result<()> {
    service.validate_in(tx)?;
    let tenant = tx.tenant_id().to_string();
    let id = run.id;
    let report = run.collection_run;
    let started = run.started_at;
    let delivery = checked_input(serde_json::to_value(run.delivery))?
        .as_str()
        .ok_or(Error::Malformed)?
        .to_owned();
    let changed=tx.with_connection(move|c|Box::pin(async move{Ok(sqlx::query("UPDATE mdm_inventory.collection_tasks SET native_delivery=$3,collection_run=$4,started_at=$5 WHERE tenant_id=$1::uuid AND id=$2 AND channel='mdm' AND (native_delivery IS DISTINCT FROM $3 OR collection_run IS DISTINCT FROM $4 OR started_at IS DISTINCT FROM $5)").bind(tenant).bind(id).bind(delivery).bind(report).bind(started).execute(c).await?.rows_affected()>0)})).await?;
    if changed {
        super::wake::run_in(&service.reconcile_messaging, tx, id).await?;
    }
    Ok(())
}
pub async fn active_count_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    now: i64,
) -> std::result::Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM mdm_inventory.collection_tasks t WHERE tenant_id=$1::uuid AND device=$2 AND deadline>$3 AND ((channel='agent' AND agent_state->>'execution' IN('not_started','running') AND agent_state->>'cancellation'<>'confirmed') OR (channel='mdm' AND native_delivery<>'cancelled' AND NOT EXISTS(SELECT 1 FROM mdm_access.collection_runs r WHERE(r.tenant_id,r.id)=(t.tenant_id,t.collection_run) AND r.sealed_at IS NOT NULL)))")
        .bind(tenant.to_string()).bind(device).bind(now).fetch_one(c).await
}
pub async fn owned_ids_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    ids: &[Uuid],
) -> std::result::Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=ANY($2)",
    )
    .bind(tenant.to_string())
    .bind(ids)
    .fetch_all(c)
    .await
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

pub async fn load_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<AgentRun> {
    run_in(tx, id, true).await
}
pub async fn read_run(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<AgentRun> {
    run_in(tx, id, false).await
}
async fn run_in(tx: &mut PgTransaction<'_>, id: Uuid, locked: bool) -> Result<AgentRun> {
    let tenant = tx.tenant_id().to_string();
    let row = tx.with_connection(move |c| Box::pin(async move {
        if locked {
            sqlx::query("SELECT id FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2 AND channel='agent' FOR UPDATE")
                .bind(&tenant).bind(id).fetch_optional(&mut *c).await?;
        }
        sqlx::query("SELECT * FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2 AND channel='agent'")
            .bind(tenant).bind(id).fetch_optional(c).await
    })).await?.ok_or(Error::NotFound)?;
    Ok(AgentRun {
        id,
        policy_version: row.try_get("policy_version")?,
        origin: stored(serde_json::from_value(row.try_get("origin")?))?,
        target: super::model::Target {
            device: row.try_get("device")?,
            registration: row.try_get("registration")?,
            generation: row.try_get("generation")?,
        },
        available_at: row.try_get("available_at")?,
        deadline: row.try_get("deadline")?,
        state: stored(serde_json::from_value(row.try_get("agent_state")?))?,
        source_objects: stored(serde_json::from_value(row.try_get("source_objects")?))?,
        result: row
            .try_get::<Option<Value>, _>("agent_result")?
            .map(|v| stored(serde_json::from_value(v)))
            .transpose()?,
    })
}

pub async fn save_run(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    run: &AgentRun,
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
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    let (previous, changed) = tx.with_connection(move |c| Box::pin(async move {
        let previous: Value = sqlx::query_scalar("SELECT agent_state FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2 AND channel='agent' FOR UPDATE")
            .bind(&tenant).bind(id).fetch_one(&mut *c).await?;
        let changed = sqlx::query("UPDATE mdm_inventory.collection_tasks SET agent_state=$3,agent_result=$4 WHERE tenant_id=$1::uuid AND id=$2 AND channel='agent' AND (agent_state IS DISTINCT FROM $3 OR agent_result IS DISTINCT FROM $4)")
            .bind(tenant).bind(id).bind(state).bind(result).execute(c).await?.rows_affected() > 0;
        Ok((previous, changed))
    })).await?;
    if !changed {
        return Ok(());
    }
    super::wake::run_in(&service.reconcile_messaging, tx, run.id).await?;
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

pub async fn pending_in(
    tx: &mut PgTransaction<'_>,
    owner: Uuid,
    version: Uuid,
    target: &super::model::Target,
    now: i64,
) -> Result<(bool, Option<i64>)> {
    let tenant = tx.tenant_id().to_string();
    let device = target.device.clone();
    let registration = target.registration;
    Ok(tx.with_connection(move |c| Box::pin(async move {
        let pending = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_inventory.collection_tasks t JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(t.tenant_id,t.policy_version) WHERE t.tenant_id=$1::uuid AND v.policy=$2 AND t.device=$3 AND t.registration=$4 AND t.deadline>$5 AND ((t.channel='agent' AND t.agent_state->>'execution' IN('not_started','running') AND t.agent_state->>'cancellation'<>'confirmed') OR (t.channel='mdm' AND t.native_delivery<>'cancelled' AND NOT EXISTS(SELECT 1 FROM mdm_access.collection_runs r WHERE(r.tenant_id,r.id)=(t.tenant_id,t.collection_run) AND r.sealed_at IS NOT NULL))))")
            .bind(&tenant).bind(owner).bind(device).bind(registration).bind(now).fetch_one(&mut *c).await?;
        let last = sqlx::query_scalar("SELECT max(coalesce(triggered_at,created_at)) FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND policy_version=$2 AND registration=$3")
            .bind(tenant).bind(version).bind(registration).fetch_one(c).await?;
        Ok((pending,last))
    })).await?)
}
pub async fn last_started_in(
    tx: &mut PgTransaction<'_>,
    version: Uuid,
    target: &super::model::Target,
) -> Result<Option<i64>> {
    let tenant = tx.tenant_id().to_string();
    let registration = target.registration;
    Ok(tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar("SELECT max(coalesce(started_at,(agent_state->>'startedAt')::bigint)) FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND policy_version=$2 AND registration=$3")
            .bind(tenant).bind(version).bind(registration).fetch_one(c).await
    })).await?)
}

pub async fn channel_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<String> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT channel FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await})).await?)
}
pub async fn native_progress_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<super::model::NativeProgress> {
    let run = native_run(tx, id).await?;
    let report = if let Some(id) = run.collection_run {
        let tenant = tx.tenant_id().to_string();
        let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT result,reason,sealed_at FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await})).await?;
        Some(super::model::NativeReport {
            id,
            result: row.try_get("result")?,
            reason: row.try_get("reason")?,
            sealed_at: row.try_get("sealed_at")?,
        })
    } else {
        None
    };
    Ok(super::model::NativeProgress {
        delivery: run.delivery,
        report,
    })
}
/// Resolve only this owner's immutable task identity for Timeline correlation.
pub async fn association_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: uuid::Uuid,
) -> std::result::Result<Option<(String, Option<uuid::Uuid>)>, sqlx::Error> {
    sqlx::query_as("SELECT device,NULL::uuid FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2")
        .bind(tenant).bind(id).fetch_optional(c).await
}
