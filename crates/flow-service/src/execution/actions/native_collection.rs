//! Native templates use existing Policy scheduling, action runs and protocol-owned CollectionRuns.
use super::{
    state::{Cancellation, Execution},
    storage as db,
};
use crate::Error;
use crate::execution::{ExecutionService, Result, storage};
use crate::planning::action_contract::FrozenNativeCollection;
use crate::planning::policies::{self, admission::ExecutionPolicy};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
pub async fn admit_policy(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<()> {
    let Some(policy) = policies::storage::read_in(&service.policy_reader, tx, id).await? else {
        return Ok(());
    };
    if !policy.enabled
        || !matches!(
            policy.definition.action,
            rss_mdm_policy::Action::NativeCollection { .. }
        )
    {
        return Ok(());
    }
    let plan = db::load_policy_version(&service.policy_reader, tx, policy.version).await?;
    let db::ScheduledPolicy::Native(native) = &plan else {
        return Err(Error::Malformed.into());
    };
    if matches!(
        native.frozen.input.schedule.trigger,
        rss_mdm_policy::schedule::Trigger::CheckIn { .. }
            | rss_mdm_policy::schedule::Trigger::Registration
    ) {
        return Ok(());
    }
    let source = native.frozen.collection.source().as_str().to_owned();
    let tenant = tx.tenant_id().to_string();
    let now = storage::now(tx).await?;
    let rows=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.policy_recovery(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(id).execute(&mut *c).await?;
        sqlx::query("SELECT r.device,r.id,r.generation FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.state='active' AND s.enabled AND s.source=$3 AND r.device>coalesce((SELECT target_after FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2),'') COLLATE \"C\" ORDER BY r.device COLLATE \"C\" LIMIT 32")
            .bind(tenant).bind(id).bind(source).fetch_all(c).await
    })).await?;
    let mut last = None;
    let count = rows.len();
    for row in rows {
        let target = super::model::Target {
            device: row.try_get("device")?,
            registration: row.try_get("id")?,
            generation: row.try_get("generation")?,
        };
        storage::lock(tx, &target.device).await?;
        super::production::accept_for_device(service, tx, &plan, &target, Uuid::new_v4(), now)
            .await?;
        last = Some(target.device);
    }
    let tenant = tx.tenant_id().to_string();
    let after = if count == 32 { last } else { None };
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.policy_recovery SET target_after=$3 WHERE tenant_id=$1::uuid AND policy=$2").bind(tenant).bind(id).bind(after).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub async fn advance_run(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &mut db::Run,
    native: &ExecutionPolicy<FrozenNativeCollection>,
    now: i64,
) -> Result<()> {
    if matches!(
        run.state.execution,
        Execution::Running | Execution::NotStarted
    ) {
        let tenant = tx.tenant_id().to_string();
        let id = run.id;
        let result:Option<(String,String)>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_as("SELECT result,reason FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NOT NULL").bind(tenant).bind(id).fetch_optional(c).await})).await?;
        if let Some((result, reason)) = result {
            if reason == "complete" {
                run.state.execution = if result == "failed" {
                    Execution::Failed
                } else {
                    Execution::Succeeded
                };
            } else if run.state.execution == Execution::NotStarted {
                run.state.cancel();
            } else {
                run.state.execution = Execution::Unknown;
            }
            run.result =
                Some(serde_json::json!({"collectionRun":run.id,"result":result,"reason":reason}));
        }
    }
    if !matches!(
        run.state.execution,
        Execution::Running | Execution::NotStarted
    ) {
        return Ok(());
    }
    if !native.authorized_in(tx, &run.target.device, now).await? {
        return Ok(());
    }
    if run.state.execution == Execution::NotStarted
        && run.state.cancellation == Cancellation::None
        && run.available_at <= now
        && run.deadline > now
    {
        let tenant = tx.tenant_id().to_string();
        let id = run.id;
        let accepted:bool=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT gateway_accepted FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(id).fetch_one(c).await})).await?;
        if !accepted {
            return Ok(());
        }
        let tenant = tx.tenant_id().to_string();
        let exists:bool=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2)").bind(tenant).bind(id).fetch_one(c).await})).await?;
        if !exists {
            let target = rss_mdm_inventory_service::collection::native::Target {
                tenant: tx.tenant_id(),
                device: run.target.device.clone(),
                registration: run.target.registration,
                generation: run.target.generation,
            };
            let definition = native.frozen.collection.clone();
            let template = native.frozen.definition.clone();
            let deadline = run.deadline;
            tx.with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_service::collection::native::start(
                        c, &target, id, definition, template, deadline,
                    )
                    .await
                    .map_err(|error| {
                        #[cfg(feature = "integration")]
                        eprintln!("native collection rejected: {error:?}");
                        let _ = error;
                        sqlx::Error::Protocol("native collection admission".into())
                    })
                })
            })
            .await?;
            if native.frozen.input.platform == rss_mdm_policy::Platform::Macos {
                let store = service.apple_store.clone();
                let tenant = tx.tenant_id().to_string();
                let facts = tx
                    .with_connection(move |c| {
                        Box::pin(
                            async move { Ok(store.prepare_native_collection(c, tenant, id).await) },
                        )
                    })
                    .await?
                    .map_err(Error::from)?;
                for fact in facts {
                    service.audit_store.append_in(tx, &fact, false).await?;
                }
                crate::worker_wake::notify_in(tx, crate::worker_wake::Work::Apple).await?;
            }
            run.state.claim(run.id, now)?;
            run.state.delivery = super::state::Delivery::Claimed {
                attempt: run.id,
                lease_until: run.deadline,
            };
        }
    }
    Ok(())
}
pub async fn settle_device(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    let registration = match storage::current_registration(tx, device).await {
        Ok(v) => Some(v),
        Err(crate::transaction::Fault::Request(Error::Conflict)) => None,
        Err(e) => return Err(e),
    };
    if let Some((registration, generation)) = registration {
        for version in policies::admission::native_versions_in(tx, registration).await? {
            let plan = db::load_policy_version(&service.policy_reader, tx, version).await?;
            let db::ScheduledPolicy::Native(native) = &plan else {
                continue;
            };
            let source = match native.frozen.input.platform {
                rss_mdm_policy::Platform::Windows => rss_mdm_inventory::ReportSource::MdmWindows,
                rss_mdm_policy::Platform::Macos => rss_mdm_inventory::ReportSource::MdmApple,
            };
            match storage::require_source(tx, registration, source).await {
                Ok(()) => (),
                Err(crate::transaction::Fault::Request(Error::Conflict | Error::Unsupported)) => {
                    continue;
                }
                Err(e) => return Err(e),
            }
            {
                let now = storage::now(tx).await?;
                let target = super::model::Target {
                    device: device.into(),
                    registration,
                    generation,
                };
                super::production::accept_for_device(
                    service,
                    tx,
                    &plan,
                    &target,
                    Uuid::new_v4(),
                    now,
                )
                .await?;
            }
        }
    }
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    let ids:Vec<Uuid>=tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT r.id FROM mdm_commands.action_runs r LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) LEFT JOIN mdm_planning.remote_operations o ON(o.tenant_id,o.id)=(r.tenant_id,r.remote_operation) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND coalesce(v.frozen,o.frozen)->>'kind'='native_collection' AND r.state->>'execution' IN('not_started','running','unknown') ORDER BY r.created_at,r.id LIMIT 64").bind(tenant).bind(device).fetch_all(c).await})).await?;
    for id in ids {
        super::recovery::recover_one(service, tx, id).await?;
    }
    Ok(())
}

/// Protocol owner marks the exact frozen read dispatched, on the Flow-owned connection.
pub async fn sent(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> std::result::Result<(), crate::Error> {
    let row = sqlx::query(
        "SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(id)
    .fetch_optional(&mut *c)
    .await
    .map_err(crate::database::db)?;
    let Some(row) = row else {
        return Ok(());
    };
    let mut state: super::state::RunState =
        serde_json::from_value(row.try_get("state").map_err(crate::database::db)?)
            .map_err(|_| Error::Malformed)?;
    if state.execution == Execution::NotStarted && state.cancellation == Cancellation::None {
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(crate::database::db)?;
        state.received(id, now)?;
        state.start(id, now)?;
        sqlx::query(
            "UPDATE mdm_commands.action_runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(tenant)
        .bind(id)
        .bind(serde_json::to_value(state).map_err(|_| Error::Malformed)?)
        .execute(c)
        .await
        .map_err(crate::database::db)?;
    }
    Ok(())
}
