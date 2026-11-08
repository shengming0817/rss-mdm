//! Enrollment persistence borrows the initiating transaction and never settles it.
use crate::enrollment::tasks::{Error, Result, checked_input, runs::Run, stored};
use rss_transactional_messaging_postgres::PgTransaction;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

pub async fn load_run(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Run> {
    run_in(profile, tx, id, true).await
}
pub async fn read_run(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Run> {
    run_in(profile, tx, id, false).await
}
async fn run_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    locked: bool,
) -> Result<Run> {
    let tenant = tx.tenant_id().to_string();
    let row = tx
        .with_connection(move |c| {
            Box::pin(async move {
                if locked {
                    sqlx::query(
                        crate::storage_profile::sql(profile).enrollment_tasks_storage_run_in_1,
                    )
                    .bind(&tenant)
                    .bind(id)
                    .fetch_optional(&mut *c)
                    .await?;
                }
                sqlx::query(crate::storage_profile::sql(profile).enrollment_tasks_storage_run_in_2)
                    .bind(tenant)
                    .bind(id)
                    .fetch_optional(c)
                    .await
            })
        })
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Run {
        id,
        policy_version: row.try_get("policy_version")?,
        origin: stored(serde_json::from_value(row.try_get("origin")?))?,
        target: crate::enrollment::tasks::Target {
            device: row.try_get("device")?,
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
    profile: rss_mdm_install_support::StorageProfile,
    service: &crate::enrollment::tasks::Transactions,
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
    let (previous, changed) = tx
        .with_connection(move |c| {
            Box::pin(async move {
                let previous: Value = sqlx::query_scalar(
                    crate::storage_profile::sql(profile).enrollment_tasks_storage_save_run_1,
                )
                .bind(&tenant)
                .bind(id)
                .fetch_one(&mut *c)
                .await?;
                let changed = sqlx::query(
                    crate::storage_profile::sql(profile).enrollment_tasks_storage_save_run_2,
                )
                .bind(tenant)
                .bind(id)
                .bind(state)
                .bind(result)
                .bind(invocation)
                .execute(c)
                .await?
                .rows_affected()
                    > 0;
                Ok((previous, changed))
            })
        })
        .await?;
    if !changed {
        return Ok(());
    }
    crate::enrollment::tasks::wake::run_in(profile, &service.reconcile_messaging, tx, run.id)
        .await?;
    use rss_mdm_task_state::{Cancellation, Execution};
    let terminal = match run.state.execution {
        Execution::Succeeded => Some("succeeded"),
        Execution::Failed => Some("failed"),
        _ if run.state.cancellation == Cancellation::Confirmed => Some("cancelled"),
        _ => None,
    };
    if let Some(status) = terminal
        && let Some(sink) = &service.events
    {
        let cancelled = previous.get("cancellation").and_then(Value::as_str) == Some("confirmed");
        if previous.get("execution").and_then(Value::as_str) != Some(status)
            && !(status == "cancelled" && cancelled)
        {
            use rss_mdm_webhook_service::{events, model::*};
            let occurred_at = now(tx).await?;
            let event = Event {
                event_id: events::identity(run.id, &format!("terminal:{status}")),
                event_type: EventType::PolicyTerminal,
                version: 1,
                occurred_at,
                tenant_id: stored(Uuid::parse_str(&tx.tenant_id().to_string()))?,
                device_id: run.target.device.clone(),
                data: EventData::Policy {
                    run_id: run.id,
                    policy_version: run.policy_version,
                    device_id: run.target.device.to_string(),

                    status: status.into(),
                },
            };
            tx.with_connection_context(&mut (sink, &event), |(sink, event), c| {
                Box::pin(async move { Ok(sink.emit(c, event).await) })
            })
            .await??;
        }
    }
    Ok(())
}

/// The caller holds the device fence across this check and admission. Unknown is
/// intentionally independent of Policy, version, device, deadline and cancellation.
pub async fn pending_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
    version: Uuid,
    target: &crate::enrollment::tasks::Target,
    now: i64,
) -> Result<(bool, Option<i64>)> {
    let tenant = tx.tenant_id().to_string();
    let target = target.clone();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_as(
                    crate::storage_profile::sql(profile).enrollment_tasks_storage_pending_in_1,
                )
                .bind(tenant)
                .bind(&target.device)
                .bind(policy)
                .bind(version)
                .bind(&target.device)
                .bind(now)
                .fetch_one(c)
                .await
            })
        })
        .await?)
}

pub async fn active_count_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &str,
    now: i64,
) -> std::result::Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        crate::storage_profile::sql(profile).enrollment_tasks_storage_active_count_on_1,
    )
    .bind(tenant.to_string())
    .bind(device)
    .bind(now)
    .fetch_one(c)
    .await
}
pub async fn owned_ids_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    ids: &[Uuid],
) -> std::result::Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).enrollment_tasks_storage_owned_ids_on_1)
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
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: &[u8],
) -> Result<Option<Value>> {
    lock_request(tx, actor, id).await?;
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let row = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query(crate::storage_profile::sql(profile).enrollment_tasks_storage_replay_1)
                    .bind(tenant)
                    .bind(actor)
                    .bind(id)
                    .fetch_optional(c)
                    .await
            })
        })
        .await?;
    row.map(|row| {
        if row.try_get::<Vec<u8>, _>("fingerprint")? != fingerprint {
            return Err(Error::Conflict.into());
        }
        Ok(row.try_get("response")?)
    })
    .transpose()
}
pub async fn receipt(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    actor: &str,
    id: Uuid,
    fingerprint: Vec<u8>,
    response: &Value,
    target: &crate::enrollment::tasks::Target,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let actor = actor.to_owned();
    let response = response.clone();
    let target = target.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).enrollment_tasks_storage_receipt_1)
                .bind(tenant)
                .bind(actor)
                .bind(id)
                .bind(fingerprint)
                .bind(response)
                .bind(&target.device)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    Ok(())
}
pub async fn lock_device(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let devices = vec![device.to_owned()];
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(crate::lifecycle::lock_devices_in(profile, c, &tenant, &devices).await)
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
    proof: &crate::enrollment::tasks::authorization::context::AuthorizedPrincipal,
    device: &str,
    permission: crate::enrollment::tasks::authorization::Permission,
) -> Result<crate::enrollment::tasks::authorization::Snapshot> {
    let snapshot = current(tx, proof).await?;
    snapshot.require(proof, permission, Some(device))?;
    Ok(snapshot)
}
pub async fn current(
    tx: &mut PgTransaction<'_>,
    proof: &crate::enrollment::tasks::authorization::context::AuthorizedPrincipal,
) -> Result<crate::enrollment::tasks::authorization::Snapshot> {
    let profile = proof.profile();
    let tenant = proof.tenant_id().to_owned();
    let instance = proof.instance_id().to_owned();
    let snapshot = tx
        .with_connection(move |c| {
            Box::pin(async move {
                crate::enrollment::tasks::authorization::lock_shared_on(
                    profile, c, &tenant, &instance,
                )
                .await
                .map_err(|_| sqlx::Error::Protocol("authorization lock".into()))?;
                Ok(crate::enrollment::tasks::authorization::snapshot_on(
                    profile, c, &tenant, &instance,
                )
                .await)
            })
        })
        .await??;
    Ok(snapshot)
}

/// Resolve only this owner's immutable task identity for Timeline correlation.
pub async fn association_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: uuid::Uuid,
) -> std::result::Result<Option<(String, Option<uuid::Uuid>)>, sqlx::Error> {
    sqlx::query_as(crate::storage_profile::sql(profile).enrollment_tasks_storage_association_on_1)
        .bind(tenant)
        .bind(id)
        .fetch_optional(c)
        .await
}
