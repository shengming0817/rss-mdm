//! Native templates use existing Policy scheduling, action runs and protocol-owned CollectionRuns.
use super::{
    state::{Cancellation, Execution},
    storage as db,
};
use crate::Error;
use crate::action_contract::FrozenNativeCollection;
use crate::sources::{self as policies, admission::ExecutionPolicy};
use crate::{ExecutionService, Result, storage};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
pub async fn admit_policy(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<bool> {
    let Some(policy) = policies::storage::read_in(&service.policy_reader, tx, id).await? else {
        return Ok(false);
    };
    if !policy.state.is_enabled()
        || !matches!(
            policy.definition.action,
            rss_mdm_policy::Action::NativeCollection { .. }
        )
    {
        return Ok(false);
    }
    let plan = db::load_policy_version(&service.policy_reader, tx, policy.version).await?;
    let db::ScheduledPolicy::Native(native) = &plan else {
        return Err(Error::Malformed.into());
    };
    let source = native.frozen.collection.source().as_str().to_owned();
    let tenant = tx.tenant_id().to_string();
    let now = storage::now(tx).await?;
    let rows=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.policy_recovery(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(&tenant).bind(id).execute(&mut *c).await?;
        sqlx::query("SELECT r.device,r.id,r.generation FROM mdm_access.registrations r JOIN mdm_access.report_sources s ON(s.tenant_id,s.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.state='active' AND s.enabled AND s.source=$3 AND r.device>coalesce((SELECT target_after FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2),'') COLLATE \"C\" ORDER BY r.device COLLATE \"C\" LIMIT 1")
            .bind(tenant).bind(id).bind(source).fetch_all(c).await
    })).await?;
    let mut last = None;
    let count = rows.len();
    for row in rows {
        let target = crate::Target {
            device: row.try_get("device")?,
            registration: row.try_get("id")?,
            generation: row.try_get("generation")?,
        };
        storage::lock(tx, &target.device).await?;
        super::production::accept_for_device(
            service,
            tx,
            &plan,
            &target,
            super::production::AdmissionTrigger::Scheduled,
            now,
        )
        .await?;
        last = Some(target.device);
    }
    let tenant = tx.tenant_id().to_string();
    let after = if count == 1 { last } else { None };
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("UPDATE mdm_commands.policy_recovery SET target_after=$3 WHERE tenant_id=$1::uuid AND policy=$2").bind(tenant).bind(id).bind(after).execute(c).await?;Ok(())})).await?;
    Ok(count == 1)
}
/// Reconcile sealed evidence without admitting, renewing or dispatching a collection.
pub async fn settle_run(tx: &mut PgTransaction<'_>, run: &mut db::Run) -> Result<()> {
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
    Ok(())
}

pub async fn advance_run(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &mut db::Run,
    native: &ExecutionPolicy<FrozenNativeCollection>,
    now: i64,
) -> Result<()> {
    settle_run(tx, run).await?;
    if !matches!(
        run.state.execution,
        Execution::Running | Execution::NotStarted
    ) {
        return Ok(());
    }
    if !native
        .authorized_in(&service.source, tx, &run.target.device, now)
        .await?
    {
        return Ok(());
    }
    if run.state.execution == Execution::NotStarted
        && run.state.cancellation == Cancellation::None
        && run.available_at <= now
        && run.deadline > now
    {
        let tenant_id = tx.tenant_id();
        let target = run.target.clone();
        let template = native.frozen.definition.clone();
        let allowed = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(
                        crate::collection_eligibility::native_on(c, tenant_id, &target, &template)
                            .await,
                    )
                })
            })
            .await??;
        if !allowed {
            return Ok(());
        }
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
                let store = service.apple_collections.clone();
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

/// Check current frozen operation grants on the same connection used by the protocol owner.
/// Called before native dispatch and before accepting a report into Inventory.
pub async fn eligible_on(
    source: &dyn crate::source_authority::SourceAuthority,
    c: &mut sqlx::PgConnection,
    p: &crate::device::DevicePrincipal,
    id: Uuid,
) -> std::result::Result<bool, crate::Error> {
    eligible_target_on(
        source,
        c,
        p.tenant(),
        &crate::Target {
            device: p.device().into(),
            registration: p.registration(),
            generation: p.generation(),
        },
        id,
    )
    .await
}

/// Retired sources have no new delivery eligibility; receipt eligibility remains separate.
pub async fn delivery_eligible_on(
    source: &dyn crate::source_authority::SourceAuthority,
    c: &mut sqlx::PgConnection,
    p: &rss_mdm_registration_service::DevicePrincipal,
    id: Uuid,
) -> std::result::Result<bool, crate::Error> {
    delivery_eligible_target_on(
        source,
        c,
        p.tenant(),
        &crate::Target {
            device: p.device().into(),
            registration: p.registration(),
            generation: p.generation(),
        },
        id,
    )
    .await
}
pub(crate) async fn delivery_eligible_target_on(
    source: &dyn crate::source_authority::SourceAuthority,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    target: &crate::Target,
    id: Uuid,
) -> std::result::Result<bool, crate::Error> {
    let version: Option<Uuid> = sqlx::query_scalar(
        "SELECT policy_version FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant.to_string())
    .bind(id)
    .fetch_optional(&mut *c)
    .await
    .map_err(crate::database::db)?
    .flatten();
    let Some(version) = version else {
        return Ok(false);
    };
    if !source.policy_readable_on(c, tenant, version).await? {
        return Ok(false);
    }
    eligible_target_on(source, c, tenant, target, id).await
}

/// Wake claims revalidate the same frozen grants under the authority/channel locks.
pub(crate) async fn eligible_target_on(
    source: &dyn crate::source_authority::SourceAuthority,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    target: &crate::Target,
    id: Uuid,
) -> std::result::Result<bool, crate::Error> {
    let row=sqlx::query("SELECT v.frozen AS frozen,r.device,r.deadline,r.state,r.source_objects,(policy.definition->>'scope')::uuid AS scope FROM mdm_commands.action_runs r LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) LEFT JOIN mdm_policy.policies policy ON(policy.tenant_id,policy.id)=(v.tenant_id,v.policy) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.device=$3 AND r.registration=$4 AND r.generation=$5 AND r.deadline>floor(extract(epoch FROM clock_timestamp())) AND (policy.state='enabled' AND policy.current_version=r.policy_version)")
        .bind(tenant.to_string()).bind(id).bind(target.device.as_str()).bind(target.registration).bind(target.generation).fetch_optional(&mut *c).await.map_err(crate::database::db)?;
    let Some(row) = row else {
        return Ok(false);
    };
    if let Some(scope) = row
        .try_get::<Option<Uuid>, _>("scope")
        .map_err(crate::database::db)?
        && !matches!(
            source
                .admission_on(
                    c,
                    tenant,
                    scope,
                    rss_mdm_inventory::Channel::Mdm,
                    target.device.as_str()
                )
                .await
                .map_err(crate::Error::from)?,
            crate::source_authority::ScopeAdmission::Eligible { .. }
        )
    {
        return Ok(false);
    }
    let state: super::state::RunState =
        serde_json::from_value(row.try_get("state").map_err(crate::database::db)?)
            .map_err(|_| Error::Malformed)?;
    if state.started_at.is_none() {
        let evidence: Vec<crate::source_authority::DeviceObject> =
            serde_json::from_value(row.try_get("source_objects").map_err(crate::database::db)?)
                .map_err(|_| Error::Malformed)?;
        if !source
            .evidence_valid_on(
                c,
                tenant,
                rss_mdm_inventory::Channel::Mdm,
                &target.device,
                &evidence,
            )
            .await?
        {
            return Ok(false);
        }
    }
    if state.cancellation != Cancellation::None
        || !matches!(state.execution, Execution::NotStarted | Execution::Running)
    {
        return Ok(false);
    }
    let frozen: crate::frozen::Frozen =
        serde_json::from_value(row.try_get("frozen").map_err(crate::database::db)?)
            .map_err(|_| Error::Malformed)?;
    let crate::frozen::Frozen::NativeCollection { action, .. } = frozen else {
        return Err(Error::Malformed);
    };
    if !crate::collection_eligibility::native_on(c, tenant, target, &action.definition).await? {
        return Ok(false);
    }
    let Some(grants) = action
        .grants
        .get(target.device.as_str())
        .or_else(|| action.grants.get("*"))
    else {
        return Ok(false);
    };
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(crate::database::db)?;
    for permission in action.permissions()? {
        let mut allowed = false;
        for grant in grants {
            if grant.valid(c, permission, now).await? {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn plan_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> std::result::Result<rss_mdm_windows_mdm::native::collection::Plan, crate::Error> {
    let frozen:serde_json::Value=sqlx::query_scalar("SELECT v.frozen FROM mdm_commands.action_runs r LEFT JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id=$1::uuid AND r.id=$2")
        .bind(tenant).bind(id).fetch_one(c).await.map_err(crate::database::db)?;
    let frozen: crate::frozen::Frozen =
        serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
    let crate::frozen::Frozen::NativeCollection { action, .. } = frozen else {
        return Err(Error::Malformed);
    };
    action.windows_plan.ok_or(Error::Malformed)
}
