use super::*;
use rss_mdm_inventory_service::collection::execution as collection;
use rss_reconcile::DurableStore;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
fn policy() -> Result<rss_reconcile::Policy> {
    Ok(rss_reconcile::Policy::try_from(
        rss_reconcile::PolicyConfig {
            claim_batch_size: 64,
            scan_budget: 64,
            concurrency: 1,
            lease_ttl: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(6),
            scan_interval: Duration::from_millis(20),
            idle_scan_interval: Duration::from_secs(5),
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(60),
            max_attempts: 1000,
        },
    )?)
}
pub(super) async fn wake(h: &Harness, collection: bool, policy: Uuid) -> Result<()> {
    let messaging = Box::pin(rss_reconcile_postgres::PgMessagingStore::new(
        h.a.resources.storage.runtime.clone(),
        h.c.execution(),
        script::transaction::deadline(),
    ))
    .await?;
    script::transaction::inspect(
        &h.a.resources.storage.runtime,
        h.c.execution(),
        (messaging, collection, policy),
        |ctx, tx| {
            Box::pin(async move {
                if ctx.1 {
                    collection::wake::policy_in(&ctx.0, tx, ctx.2).await?;
                } else {
                    script::wake::policy_in(&ctx.0, tx, ctx.2).await?;
                }
                Ok(())
            })
        },
    )
    .await?;
    Ok(())
}
async fn converged(h: &Harness, domain: &str, count: i64) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20),async {
        loop {
            let state:(i64,i64)=sqlx::query_as("SELECT count(*),count(*) FILTER(WHERE result='converged' AND next_run IS NULL AND token IS NULL) FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2").bind(h.c.tenant.to_string()).bind(domain).fetch_one(&h.c.operator).await?;
            if state==(count,count) {break;}
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}
async fn owner_policy(h: &Harness, collection: bool) -> Result<(Uuid, Uuid)> {
    Ok(if collection {
        let (d, f, _) = super::mixed::agent(h)?;
        let p = Uuid::new_v4();
        (p, super::mixed::publish(h, p, 1, d, f).await?)
    } else {
        h.policy("checkpoint").await?
    })
}
async fn seed_runs(h: &Harness, collection: bool) -> Result<(Uuid, Vec<Uuid>)> {
    let (policy, version) = owner_policy(h, collection).await?;
    let first = if collection {
        super::mixed::run(h, version, now()).await?
    } else {
        h.run(version, "checkpoint", now() + 300).await?
    };
    let mut cancelled = rss_mdm_task_state::RunState::new(now() + 300, now())?;
    cancelled.cancel();
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query(if collection {"UPDATE mdm_inventory.collection_tasks SET agent_state=$3 WHERE tenant_id=$1::uuid AND id=$2"} else {"UPDATE mdm_script.runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2"}).bind(h.c.tenant.to_string()).bind(first).bind(serde_json::to_value(cancelled)?).execute(&mut *tx).await?;
    sqlx::query(if collection {"INSERT INTO mdm_inventory.collection_tasks (expected_epoch,tenant_id, id, occurrence, policy_version, channel, origin, source_objects, device, created_at, available_at, deadline, agent_state, dispatch_fingerprint) SELECT expected_epoch,tenant_id, gen_random_uuid(), 'page:' || n, policy_version, channel, origin, source_objects, device, created_at, available_at, deadline, agent_state, dispatch_fingerprint FROM mdm_inventory.collection_tasks CROSS JOIN generate_series(1, 32) AS n WHERE tenant_id = CAST($1 AS uuid) AND id = $2"} else {"INSERT INTO mdm_script.runs (expected_epoch,tenant_id, id, occurrence, policy_version, resource_id, origin, source_objects, device, created_at, available_at, deadline, state, dispatch_fingerprint) SELECT expected_epoch,tenant_id, gen_random_uuid(), 'page:' || n, policy_version, resource_id, origin, source_objects, device, created_at, available_at, deadline, state, dispatch_fingerprint FROM mdm_script.runs CROSS JOIN generate_series(1, 32) AS n WHERE tenant_id = CAST($1 AS uuid) AND id = $2"}).bind(h.c.tenant.to_string()).bind(first).execute(&mut *tx).await?;
    tx.commit().await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(if collection {
        "SELECT id FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid ORDER BY id"
    } else {
        "SELECT id FROM mdm_script.runs WHERE tenant_id=$1::uuid ORDER BY id"
    })
    .bind(h.c.tenant.to_string())
    .fetch_all(&h.c.operator)
    .await?;
    assert_eq!(ids.len(), 33);
    Ok((policy, ids))
}
async fn first_page(
    h: &Harness,
    collection: bool,
    policy: Uuid,
    ids: &[Uuid],
) -> Result<rss_reconcile::Scope> {
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let force = CancellationToken::new();
    let stop = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &force);
    let store = rss_mdm_work_page::scheduler::Scheduler::new(
        h.a.resources.storage.read_pool.clone(),
        &control,
    )
    .await?;
    let scope = if collection {
        collection::wake::scope(h.c.tenant)
    } else {
        script::wake::scope(h.c.tenant)
    };
    let entity = format!("policy:{policy}");
    let notify = tokio::sync::Notify::new();
    let observe = |event| {
        if let rss_reconcile::Observation::Deferred { target } = event
            && target.entity() == entity
        {
            stop.cancel();
        }
    };
    let report = if collection {
        rss_reconcile::run_with_notify(
            &store,
            h.a.collection_work.as_ref(),
            &scope,
            self::policy()?,
            &control,
            &stop,
            &notify,
            observe,
        )
        .await?
    } else {
        rss_reconcile::run_with_notify(
            &store,
            h.a.script_work.as_ref(),
            &scope,
            self::policy()?,
            &control,
            &stop,
            &notify,
            observe,
        )
        .await?
    };
    assert!(report.deferred > 0);
    assert_eq!(report.execution_failed, 0);
    let row:(Uuid,bool,bool)=sqlx::query_as(if collection {"SELECT recovery_after,runs_done,input_window>input_consumed FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2"} else {"SELECT recovery_after,runs_done,input_window>input_consumed FROM mdm_script.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2"}).bind(h.c.tenant.to_string()).bind(policy).fetch_one(&h.c.operator).await?;
    assert_eq!(row, (ids[31], false, true));
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity LIKE 'run:%'").bind(h.c.tenant.to_string()).bind(scope.reconciler()).fetch_one(&h.c.operator).await?;
    assert_eq!(count, 32);
    Ok(scope)
}
async fn resume(
    h: &Harness,
    collection: bool,
    policy: Uuid,
    scope: &rss_reconcile::Scope,
) -> Result<()> {
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    let notify = Arc::new(tokio::sync::Notify::new());
    let registration = if collection {
        h.a.collection_work.clone().registration(
            h.a.resources.background.tasks,
            h.a.resources.background.tasks_drain,
            notify,
        )
    } else {
        h.a.script_work.clone().registration(
            h.a.resources.background.tasks,
            h.a.resources.background.tasks_drain,
            notify,
        )
    };
    let status = launch.stage_deferred_task_with_token(registration.critical());
    launch.finish();
    converged(h, scope.reconciler(), 34).await?;
    assert!(stack.shutdown().join().await?.is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
    let settled:bool=sqlx::query_scalar(if collection {"SELECT input_consumed=input_revision AND runs_done FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2"} else {"SELECT input_consumed=input_revision AND runs_done FROM mdm_script.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2"}).bind(h.c.tenant.to_string()).bind(policy).fetch_one(&h.c.operator).await?;
    assert!(settled);
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let store = rss_mdm_work_page::scheduler::Scheduler::new(
        h.a.resources.storage.read_pool.clone(),
        &control,
    )
    .await?;
    assert!(
        store
            .claim_due(scope, 64, 64, Duration::from_secs(30), &control)
            .await?
            .claims
            .is_empty()
    );
    Ok(())
}
async fn checkpoint_restart(collection: bool) -> Result<()> {
    let mut h = Harness::open().await?;
    let (policy, ids) = seed_runs(&h, collection).await?;
    wake(&h, collection, policy).await?;
    let scope = first_page(&h, collection, policy, &ids).await?;
    let a = Fixture::open(&h.c).await?;
    let (audit, delivery) = super::delivery(&h.c, &a).await?;
    drop(std::mem::replace(&mut h.delivery, delivery));
    drop(std::mem::replace(&mut h.audit, audit));
    Fixture::close(std::mem::replace(&mut h.a, a)).await?;
    resume(&h, collection, policy, &scope).await?;
    wake(&h, collection, policy).await?;
    resume(&h, collection, policy, &scope).await?;
    h.close().await
}
#[tokio::test]
#[ignore = "T2: real Script worker persists one page, resumes after reconstruction, converges and accepts a new wake"]
async fn script_checkpoint_restart_and_convergence() -> Result<()> {
    checkpoint_restart(false).await
}
#[tokio::test]
#[ignore = "T2: real Collection worker persists one page, resumes after reconstruction, converges and accepts a new wake"]
async fn collection_checkpoint_restart_and_convergence() -> Result<()> {
    checkpoint_restart(true).await
}

async fn native_notifications(h: &Harness, task: Uuid) -> Result<(bool, i64, i64)> {
    let event = rss_mdm_webhook_service::events::identity(task, "terminal:expired");
    Ok(sqlx::query_as("SELECT terminal_notified,(SELECT count(*) FROM mdm_webhook.events WHERE tenant_id=$1::uuid AND id=$3),(SELECT count(*) FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND message_id=$4) FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2")
        .bind(h.c.tenant.to_string()).bind(task).bind(event).bind(event.to_string()).fetch_one(&h.c.operator).await?)
}
async fn drain_native(h: &Harness, task: Uuid) -> Result<()> {
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let stop = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &cancel);
    let store = rss_mdm_work_page::scheduler::Scheduler::new(
        h.a.resources.storage.read_pool.clone(),
        &control,
    )
    .await?;
    let scope = collection::wake::scope(h.c.tenant);
    let target = rss_reconcile::Target::new(scope.clone(), format!("run:{task}"))?;
    store
        .wake(
            &target,
            &rss_reconcile::ResourceSet::empty(h.c.tenant),
            &control,
        )
        .await?;
    let notify = tokio::sync::Notify::new();
    let (report, settled) = tokio::join!(
        rss_reconcile::run_with_notify(
            &store,
            h.a.collection_work.as_ref(),
            &scope,
            policy()?,
            &control,
            &stop,
            &notify,
            |_| {}
        ),
        async {
            let result = converged(h, scope.reconciler(), 1).await;
            stop.cancel();
            result
        }
    );
    settled?;
    assert_eq!(report?.execution_failed, 0);
    Ok(())
}
#[tokio::test]
#[ignore = "T2: an independently timed-out native report emits its terminal event atomically and recovery converges"]
async fn native_timeout_notification_survives_finalizer_and_rollback() -> Result<()> {
    let h = Harness::open().await?;
    let execution_binding = h.c.execution();
    let (_, task, _) = super::retirement::native(&h, None).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_access.collection_runs SET deadline=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=(SELECT collection_run FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2)")
        .bind(h.c.tenant.to_string()).bind(task).execute(&mut *tx).await?;
    tx.commit().await?;
    script::transaction::run(
        &h.audit,
        &h.a.resources.storage.runtime,
        h.c.execution(),
        &request(&h.c),
        &h.audit,
        |audit, tx| {
            Box::pin(async move {
                let tenant = tx.tenant_id().to_string();
                let (count, facts) = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            let mut facts = Vec::new();
                            let count = rss_mdm_inventory_service::collection::store::expire_timed(
                                execution_binding,
                                rss_mdm_install_support::StorageProfile::Mdm,
                                c,
                                &mut facts,
                                &tenant,
                            )
                            .await;
                            Ok((count, facts))
                        })
                    })
                    .await?;
                assert_eq!(count.map_err(script::Error::from)?, 1);
                audit.append_batch_in(tx, &facts).await?;
                Ok(())
            })
        },
    )
    .await?;
    assert_eq!(native_notifications(&h, task).await?, (false, 0, 0));
    // A failure after emitting must roll back both the event and completion receipt.
    let failed: std::result::Result<(), _> = script::transaction::run(
        &h.audit,
        &h.a.resources.storage.runtime,
        h.c.execution(),
        &request(&h.c),
        (&h.a.collections, h.c.execution()),
        |(collections, execution), tx| {
            Box::pin(async move {
                collection::recovery::recover_one(*execution, collections, tx, task).await?;
                Err(script::Error::Conflict.into())
            })
        },
    )
    .await;
    assert!(
        matches!(failed, Err(script::Error::Conflict)),
        "rollback outcome: {failed:?}"
    );
    assert_eq!(native_notifications(&h, task).await?, (false, 0, 0));
    drain_native(&h, task).await?;
    assert_eq!(native_notifications(&h, task).await?, (true, 1, 1));
    drain_native(&h, task).await?;
    assert_eq!(native_notifications(&h, task).await?, (true, 1, 1));
    h.close().await
}

#[tokio::test]
#[ignore = "T2: a real Script store acquisition failure survives another owner scan and relay, then clears only after its own successful scan"]
async fn actual_owner_scan_is_required_to_clear_readiness_failure() -> Result<()> {
    use rss_mdm_recovery_observation::Phase;
    let h = Harness::open().await?;
    let other = Harness::open().await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(500))
        .connect_with(
            h.c.inputs
                .database("shared", "mdm_scheduler_runtime")
                .options()?,
        )
        .await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let store = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
    let worker = script::worker::Worker::new(
        h.c.database.archive_pool(),
        h.c.execution().storage(),
        h.a.scripts.clone(),
        store,
        rss_mdm_work_page::capacity::Capacity::new(std::num::NonZeroUsize::new(1).unwrap()),
    )?;
    let held = pool.acquire().await?;
    let scope = script::wake::scope(h.c.tenant);
    assert!(
        worker
            .recovery_store()
            .claim_due(&scope, 1, 64, Duration::from_secs(30), &control)
            .await
            .is_err()
    );
    let failed = worker.health().recovery;
    assert!(matches!(failed, Phase::Failed(_)));
    h.a.collection_work
        .recovery_store()
        .claim_due(
            &collection::wake::scope(h.c.tenant),
            1,
            64,
            Duration::from_secs(30),
            &control,
        )
        .await?;
    worker.record_relay_health(&Ok(0));
    assert_eq!(worker.health().recovery, failed);
    drop(held);
    worker
        .recovery_store()
        .claim_due(
            &script::wake::scope(other.c.tenant),
            1,
            64,
            Duration::from_secs(30),
            &control,
        )
        .await?;
    assert_eq!(
        worker.health().recovery,
        failed,
        "another tenant scan cannot clear this failure"
    );
    assert!(
        worker
            .recovery_store()
            .claim_due(&scope, 1, 64, Duration::from_secs(30), &control)
            .await?
            .claims
            .is_empty()
    );
    assert_eq!(worker.health().recovery, Phase::Healthy);
    drop(worker);
    pool.close().await;
    for host in [&h, &other] {
        let input = w::TaskClaimRequest::new(
            Uuid::new_v4(),
            vec![w::ExecutorProfile::PowerShell7],
            context(),
        )?;
        host.delivery
            .claim(&host.p, &input, &request(&host.c))
            .await?;
    }
    // The same worker must move past an old epoch and deliver another tenant's real outbox work.
    let (blocked, ready) = if h.c.tenant.to_string() < other.c.tenant.to_string() {
        (&h, &other)
    } else {
        (&other, &h)
    };
    let (_, old_version) = blocked.policy("relay-old").await?;
    let old = Uuid::new_v4();
    assert!(matches!(
        blocked.admit(old_version, old).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));
    let (_, version) = ready.policy("relay-current").await?;
    let pending = Uuid::new_v4();
    assert!(matches!(
        ready.admit(version, pending).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));
    let accepted = || async {
        sqlx::query_scalar::<_, bool>(
            "SELECT gateway_accepted FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(ready.c.tenant.to_string())
        .bind(pending)
        .fetch_one(&ready.c.operator)
        .await
    };
    assert!(!accepted().await?);
    assert_eq!(sqlx::query("UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid AND epoch=1")
        .bind(blocked.c.tenant.to_string()).execute(&blocked.c.operator).await?.rows_affected(), 1);
    let stop = CancellationToken::new();
    let relay = crate::assembly::task_relay::Relay::new(2, h.c.execution().storage(), &stop);
    let work = h.a.script_work.clone();
    let task = tokio::spawn(async move { crate::assembly::task_relay::script(&relay, work).await });
    let observed = tokio::time::timeout(Duration::from_secs(20), async {
        while !accepted().await? {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    stop.cancel();
    task.await?;
    observed??;
    let epoch: i64 = sqlx::query_scalar(
        "SELECT expected_epoch FROM mdm_script.runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(blocked.c.tenant.to_string())
    .bind(old)
    .fetch_one(&blocked.c.operator)
    .await?;
    assert_eq!(epoch, 1, "relay does not retag old work");
    other.close().await?;

    h.close().await
}

#[tokio::test]
#[ignore = "T2: the registered Script worker survives a real claim pool timeout and advances another tenant"]
async fn recoverable_batch_scan_failure_does_not_stop_other_tenants() -> Result<()> {
    let h = Harness::open().await?;
    let other = Harness::open().await?;
    let (first, second) = if h.c.tenant.to_string() < other.c.tenant.to_string() {
        (&h, &other)
    } else {
        (&other, &h)
    };
    for host in [first, second] {
        let (policy, _) = host.policy("scan-failure").await?;
        wake(host, false, policy).await?;
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(500))
        .connect_with(
            h.c.inputs
                .database("shared", "mdm_scheduler_runtime")
                .options()?,
        )
        .await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let force = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &force);
    let store = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
    let worker = Arc::new(script::worker::Worker::new(
        h.c.database.archive_pool(),
        h.c.execution().storage(),
        h.a.scripts.clone(),
        store,
        rss_mdm_work_page::capacity::Capacity::new(std::num::NonZeroUsize::new(1).unwrap()),
    )?);
    let held = pool.acquire().await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    let status = launch.stage_deferred_task_with_token(
        worker
            .clone()
            .registration(
                policy()?,
                Duration::from_secs(20),
                Arc::new(tokio::sync::Notify::new()),
            )
            .critical(),
    );
    launch.finish();
    let failed = tokio::time::timeout(Duration::from_secs(10), async {
        while !matches!(
            worker.health().recovery,
            rss_mdm_recovery_observation::Phase::Failed(_)
        ) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    drop(held);
    let progressed = converged(second, script::wake::scope(second.c.tenant).reconciler(), 1).await;
    let shutdown = stack.shutdown().join().await?;
    assert!(shutdown.is_clean());
    assert_eq!(
        status.wait_stopped().await,
        rss_runtime::TaskExit::Cancelled
    );
    failed?;
    progressed?;
    drop(worker);
    pool.close().await;
    other.close().await?;
    h.close().await
}

#[path = "discovery.rs"]
mod discovery;

async fn registered_relay(
    h: &Harness,
    hint: Arc<tokio::sync::Notify>,
) -> Result<rss_runtime::ShutdownStack> {
    let r = &h.a.resources;
    let owner = planning::owner(&h.c, "mdm_policy_runtime").await?;
    let app = crate::assembly::policy::application(
        &r.background,
        &owner,
        h.c.execution(),
        &[7; 32],
        Arc::new(crate::clock::SystemClock),
        r.protection.clone(),
        None,
    )
    .await?;
    let events = crate::assembly::policy::events(
        h.c.execution(),
        app.clone(),
        Arc::new(crate::assembly::policy::EventInputs {
            source: r.source.clone(),
            protection: r.protection.clone(),
            instance: h.c.inputs.installation.instance_id.clone(),
        }),
        h.a.software.materials.clone(),
        h.a.registration.materials.clone(),
        Vec::new(),
    )
    .await?;
    let policy = rss_mdm_policy_service::worker::PolicyWork::new(
        h.c.database.archive_pool(),
        h.c.execution().storage(),
        app,
        events,
        r.storage.reconcile.clone(),
    );
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut startup = stack.startup()?;
    startup.stage_resource(rss_runtime::DynManagedResource::new_box(
        crate::owner_storage::Resource::new(owner.runtime, "relay-policy-test"),
    ));
    let mut launch = startup.commit();
    launch.stage_task_with_token(
        crate::assembly::task_relay::registration(
            policy,
            h.a.service.clone(),
            h.a.script_work.clone(),
            h.a.collection_work.clone(),
            h.a.software.service.clone(),
            h.a.registration.native.clone(),
            h.a.registration.worker.clone(),
            h.a.access_execution.worker.clone(),
            Vec::new(),
            None,
            4,
            h.c.execution().storage(),
            hint,
        )
        .critical(),
    );
    launch.finish();
    Ok(stack)
}

async fn accept_collection(h: &Harness) -> Result<Uuid> {
    let (definition, frozen, template) = super::mixed::agent(h)?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_access.report_sources(tenant_id, device, source, epoch, enabled) VALUES($1::uuid,$2,'agent.native',$3,TRUE)")
        .bind(h.c.tenant.to_string()).bind(h.p.device().into_uuid()).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    tx.commit().await?;
    let version = super::mixed::publish(h, Uuid::new_v4(), 1, definition, frozen).await?;
    let input = w::TaskClaimRequest::new(
        Uuid::new_v4(),
        vec![w::ExecutorProfile::PowerShell7],
        context(),
    )?
    .with_environment(rss_mdm_agent_wire::CollectionEnvironment {
        edition: None,
        tools: Default::default(),
        native_engines: template.spec().plan.requirements(),
    })?;
    h.delivery.claim(&h.p, &input, &request(&h.c)).await?;
    Ok(sqlx::query_scalar("SELECT id FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND policy_version=$2")
        .bind(h.c.tenant.to_string()).bind(version).fetch_one(&h.c.operator).await?)
}

#[tokio::test]
#[ignore = "T2: registered relay overlaps two devices, admits another tenant and owner, then drains on shutdown"]
async fn command_relay_settles_another_tenant_while_first_run_is_locked() -> Result<()> {
    let h = Harness::open().await?;
    let late = Harness::open().await?;
    let trust: serde_json::Value = sqlx::query_scalar("SELECT body FROM mdm_task_signing.versions WHERE tenant_id=$1 AND usage='agent_task' AND revision=1")
        .bind(Uuid::from_bytes(h.c.tenant.octets())).fetch_one(&h.c.operator).await?;
    let (second, _, scope) = Harness::endpoint(&h.c, &serde_json::from_value(trust)?).await?;
    for (host, agent) in [(&h, &h.p), (&h, &second), (&late, &late.p)] {
        let announcement = w::TaskClaimRequest::new(
            Uuid::new_v4(),
            vec![w::ExecutorProfile::PowerShell7],
            context(),
        )?;
        host.delivery
            .claim(agent, &announcement, &request(&host.c))
            .await?;
    }
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let (_, version) = h.policy("relay-first").await?;
    let (_, peer_version) = h.policy_in_scope("relay-peer", "system", scope).await?;
    let (_, refill_version) = h.policy_in_scope("relay-refill", "system", scope).await?;
    let (_, late_version) = late.policy("relay-late").await?;
    let (_, restart_version) = late.policy("relay-restart").await?;
    assert!(matches!(
        h.admit(version, a).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));
    assert!(matches!(
        h.admit_on(peer_version, b, *second.device()).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));
    let collection = accept_collection(&h).await?;
    let mut lock = command::seed_transaction(&h.c).await?;
    sqlx::query("SELECT 1 FROM mdm_script.runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
        .bind(Uuid::from_bytes(h.c.tenant.octets()))
        .bind(a)
        .fetch_one(&mut *lock)
        .await?;
    let hint = Arc::new(tokio::sync::Notify::new());
    // The second host observed an uncertain outcome for b. Its own readback
    // must distinguish b's publication from the other pending or leased heads.
    let binding = h.c.execution();
    let receipt: (String, Vec<u8>) = sqlx::query_as(
        "SELECT domain,fingerprint FROM rss_transactional_messaging.outbox WHERE tenant_id=$1 AND message_id=$2",
    ).bind(Uuid::from_bytes(h.c.tenant.octets())).bind(format!("script.{b}")).fetch_one(&h.c.operator).await?;
    let message = rss_mdm_recovery_observation::RelayMessage {
        domain: rss_transactional_messaging::message::MessagingDomain::parse(&receipt.0)?,
        id: rss_transactional_messaging::message::MessageId::parse(&format!("script.{b}"))?,
        fingerprint: rss_transactional_messaging::message::MessageFingerprint::from_bytes(
            receipt
                .1
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid outbox fingerprint"))?,
        ),
    };
    let observer = &late.a.script_work;
    observer.observe_relay(binding, Some(&message), Err(&script::Error::CommitUnknown));
    crate::assembly::task_relay::verify_publication(binding, observer.relay_check(binding)).await;
    assert!(matches!(
        observer.health().relay,
        Some(rss_mdm_recovery_observation::Phase::Failed(_))
    ));
    let stack = registered_relay(&h, hint.clone()).await?;
    let status = |message: String| {
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM rss_transactional_messaging.outbox WHERE message_id=$1",
        )
        .bind(message)
        .fetch_one(&h.c.operator)
    };
    let wait = |message: String, expected: &'static str| async move {
        tokio::time::timeout(Duration::from_secs(15), async {
            while status(message.clone()).await? != expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?
    };
    wait(format!("script.{b}"), "published").await?;
    wait(format!("collection.{collection}"), "published").await?;
    assert_eq!(status(format!("script.{a}")).await?, "publishing");
    crate::assembly::task_relay::verify_publication(binding, observer.relay_check(binding)).await;
    assert_eq!(
        observer.health().relay,
        Some(rss_mdm_recovery_observation::Phase::Healthy)
    );
    let refill = Uuid::new_v4();
    assert!(matches!(
        h.admit_on(refill_version, refill, *second.device()).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));
    let arrived = Uuid::new_v4();
    assert!(matches!(
        late.admit(late_version, arrived).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));
    hint.notify_one();
    wait(format!("script.{refill}"), "published").await?;
    wait(format!("script.{arrived}"), "published").await?;
    assert_eq!(status(format!("script.{a}")).await?, "publishing");
    let drain = stack.shutdown();
    let restart = Uuid::new_v4();
    assert!(matches!(
        late.admit(restart_version, restart).await?,
        w::PolicyEventDecision::Accepted { .. }
    ));
    hint.notify_one();
    lock.rollback().await?;
    assert!(drain.join().await?.is_clean());
    assert_eq!(status(format!("script.{a}")).await?, "published");
    assert_eq!(status(format!("script.{restart}")).await?, "pending");
    let stack = registered_relay(&h, hint).await?;
    wait(format!("script.{restart}"), "published").await?;
    assert!(stack.shutdown().join().await?.is_clean());
    let scripts: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_script.runs r JOIN rss_transactional_messaging.outbox o
        ON o.tenant_id=r.tenant_id AND o.message_id='script.'||r.id::text
        WHERE r.id=ANY($1) AND r.gateway_accepted AND o.status='published' AND o.fingerprint=r.dispatch_fingerprint")
        .bind([a,b,refill,arrived,restart].as_slice()).fetch_one(&h.c.operator).await?;
    assert_eq!(scripts, 5);
    let accepted: bool = sqlx::query_scalar(
        "SELECT gateway_accepted FROM mdm_inventory.collection_tasks WHERE tenant_id=$1 AND id=$2",
    )
    .bind(Uuid::from_bytes(h.c.tenant.octets()))
    .bind(collection)
    .fetch_one(&h.c.operator)
    .await?;
    assert!(accepted);
    late.close().await?;
    h.close().await
}

#[derive(Clone, Copy)]
enum TaskOwner {
    Script,
    Collection,
    Enrollment,
    Access,
    Credentials(rss_mdm_install_support::StorageProfile),
}
impl TaskOwner {
    fn table(self) -> &'static str {
        use rss_mdm_install_support::StorageProfile::*;
        match self {
            Self::Script => "mdm_script.policy_recovery",
            Self::Collection => "mdm_inventory.collection_policy_recovery",
            Self::Enrollment => "mdm_registration_tasks.policy_recovery",
            Self::Access => "rss_da.access_policy_recovery",
            Self::Credentials(Mdm) => "mdm_recovery_tasks.policy_recovery",
            Self::Credentials(Da) => "rss_da.credential_policy_recovery",
        }
    }
    async fn seed(self, h: &Harness) -> Result<Uuid> {
        let id = if matches!(self, Self::Access) {
            use rss_mdm_policy_postgres::device_access::{Publication, Target, publish_on};
            let policy = Publication {
                id: Uuid::new_v4(),
                version: Uuid::new_v4(),
                revision: 1,
                target: Target::TenantDefault,
                enabled: false,
                managed_fields: vec![],
                configuration: w::AccessConfiguration {
                    mac: None,
                    windows: w::AccessWindowsConfiguration::Whfb,
                    self_enrollment: false,
                    enabled: false,
                    role: None,
                },
            };
            let mut tx = command::seed_transaction(&h.c).await?;
            publish_on(
                &mut tx,
                Uuid::from_bytes(h.c.tenant.octets()),
                &policy,
                0,
                json!({"kind":"system"}),
                now(),
            )
            .await?;
            tx.commit().await?;
            policy.id
        } else {
            owner_policy(h, matches!(self, Self::Collection)).await?.0
        };
        let runtime = h.a.resources.storage.runtime.clone();
        let messaging = rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            h.c.execution(),
            script::transaction::deadline(),
        )
        .await?;
        runtime.local_tx_with_context(h.c.execution(),script::transaction::deadline(),(&messaging,self),|(store,owner),tx| Box::pin(async move {
            let result=match owner {
                Self::Script => script::wake::policy_in(store,tx,id).await.map_err(|e| format!("{e:?}")),
                Self::Collection => collection::wake::policy_in(store,tx,id).await.map_err(|e| format!("{e:?}")),
                Self::Enrollment => rss_mdm_registration_service::enrollment::tasks::wake::policy_in(rss_mdm_install_support::StorageProfile::Mdm,store,tx,id).await.map_err(|e| format!("{e:?}")),
                Self::Access => rss_mdm_device_access_postgres::device_access::execution::wake::policy_in(store,tx,id).await.map_err(|e| format!("{e:?}")),
                Self::Credentials(profile) => rss_mdm_recovery_credentials::tasks::wake::policy_in(*profile,store,tx,id).await.map_err(|e| format!("{e:?}")),
            };
            result.map_err(|e| sqlx::Error::Protocol(e).into())
        })).await.fold(Ok,Err,Err,Err,Err,Err)?;
        Ok(id)
    }
}

async fn locked_policy_admits_peer(owner: TaskOwner) -> Result<()> {
    use crate::authority_t2_support::{blocked_attempt, wait_for_blocked_attempt};
    let first = Harness::open().await?;
    let second = Harness::open().await?;
    let (a, b) = if first.c.tenant.to_string() < second.c.tenant.to_string() {
        (&first, &second)
    } else {
        (&second, &first)
    };
    let slow = owner.seed(a).await?;
    let mut blocker = a.c.operator.begin().await?;
    // Table names come exclusively from the closed TaskOwner enum.
    let lock = sqlx::AssertSqlSafe(format!(
        "SELECT pg_backend_pid() FROM {} WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE",
        owner.table()
    ));
    let pid = sqlx::query_scalar(lock)
        .bind(a.c.tenant.to_string())
        .bind(slow)
        .fetch_one(&mut *blocker)
        .await?;
    let notify = Arc::new(tokio::sync::Notify::new());
    let config = &a.a.resources.background;
    let registration = match owner {
        TaskOwner::Script => {
            a.a.script_work
                .clone()
                .registration(config.tasks, config.tasks_drain, notify.clone())
        }
        TaskOwner::Collection => a.a.collection_work.clone().registration(
            config.tasks,
            config.tasks_drain,
            notify.clone(),
        ),
        TaskOwner::Enrollment => a.a.registration.worker.clone().registration(
            config.tasks,
            config.tasks_drain,
            notify.clone(),
        ),
        TaskOwner::Access => a.a.access_execution.worker.clone().registration(
            config.tasks,
            config.tasks_drain,
            notify.clone(),
        ),
        TaskOwner::Credentials(profile) => {
            let r = &a.a.resources;
            let assembly = crate::assembly::credential_execution::assemble(
                r.storage.discovery_pool.clone(),
                &r.config,
                &r.background,
                r.storage.runtime.clone(),
                a.c.execution(),
                r.storage.audit.clone(),
                r.protection.clone(),
                crate::assembly::credential_owners_t2::protection(&a.c, "old")?,
                r.source.clone(),
                r.storage.reconcile.clone(),
                r.storage.worker_budget.clone(),
            )
            .await?;
            assembly
                .worker
                .into_iter()
                .find(|w| w.profile() == profile)
                .expect("configured credential owner")
                .registration(config.tasks, config.tasks_drain, notify.clone())
        }
    };
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_deferred_task_with_token(registration.critical());
    launch.finish();
    let check=tokio::time::timeout(Duration::from_secs(25),async {
        let attempt=wait_for_blocked_attempt(&a.c.operator,pid,owner.table()).await?;
        let peer=owner.seed(b).await?;
        notify.notify_one();
        let receipt=format!("SELECT input_consumed=input_revision AND runs_done FROM {} WHERE tenant_id=$1::uuid AND policy=$2",owner.table());
        while !sqlx::query_scalar::<_,bool>(sqlx::AssertSqlSafe(receipt.as_str())).bind(b.c.tenant.to_string()).bind(peer).fetch_optional(&b.c.operator).await?.unwrap_or(false){
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::ensure!(blocked_attempt(&a.c.operator,pid,owner.table()).await?==Some(attempt),"peer missed the blocked business attempt for {}",owner.table());
        Ok::<_,anyhow::Error>(())
    }).await;
    blocker.rollback().await?;
    anyhow::ensure!(stack.shutdown().join().await?.is_clean());
    second.close().await?;
    first.close().await?;
    check?
}
macro_rules! recovery_isolation {
    ($test:ident,$owner:expr) => {
        #[tokio::test]
        #[ignore = "T2: the registered recovery owner commits a late tenant's original receipt during a peer business lock"]
        async fn $test() -> Result<()> { locked_policy_admits_peer($owner).await }
    };
}
recovery_isolation!(
    script_recovery_commits_during_a_peer_business_lock,
    TaskOwner::Script
);
recovery_isolation!(
    collection_recovery_commits_during_a_peer_business_lock,
    TaskOwner::Collection
);
recovery_isolation!(
    enrollment_recovery_commits_during_a_peer_business_lock,
    TaskOwner::Enrollment
);
recovery_isolation!(
    device_access_recovery_commits_during_a_peer_business_lock,
    TaskOwner::Access
);
recovery_isolation!(
    mdm_credentials_recovery_commits_during_a_peer_business_lock,
    TaskOwner::Credentials(rss_mdm_install_support::StorageProfile::Mdm)
);
recovery_isolation!(
    da_credentials_recovery_commits_during_a_peer_business_lock,
    TaskOwner::Credentials(rss_mdm_install_support::StorageProfile::Da)
);

fn start_owner(
    registration: rss_runtime::ManagedTaskRegistration,
) -> Result<rss_runtime::ShutdownStack> {
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(30))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut start = stack.startup()?.commit();
    start.stage_task_with_token(registration);
    start.finish();
    Ok(stack)
}

#[tokio::test]
#[ignore = "T2: Script and Collection share eight execution slots, refill a single freed slot, and stop claiming on shutdown"]
async fn registered_owners_share_capacity_and_drain() -> Result<()> {
    use crate::authority_t2_support::{blocked_attempt, wait_for_blocked_attempt};
    let a = Harness::open_in("worker_capacity").await?;
    let b = Harness::open_in("worker_capacity").await?;
    let config = &a.a.resources.background;
    let width = config.tasks.concurrency();
    anyhow::ensure!(width == 8);
    for _ in 1..width {
        TaskOwner::Script.seed(&a).await?;
    }
    for _ in 0..2 {
        TaskOwner::Collection.seed(&b).await?;
    }
    let mut held = a.c.operator.begin().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM mdm_script.policy_recovery WHERE tenant_id=$1::uuid FOR UPDATE")
        .bind(a.c.tenant.to_string()).fetch_all(&mut *held).await?[0];
    let mut peer = b.c.operator.begin().await?;
    let peer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=$1::uuid FOR UPDATE")
        .bind(b.c.tenant.to_string()).fetch_all(&mut *peer).await?[0];
    let notify = Arc::new(tokio::sync::Notify::new());
    let script = start_owner(a.a.script_work.clone().registration(
        config.tasks,
        config.tasks_drain,
        notify.clone(),
    ))?;
    let counts = || {
        sqlx::query_as::<_,(i64,i64)>("SELECT count(*) FILTER(WHERE tenant_id=$1::uuid AND reconciler=$3), count(*) FILTER(WHERE tenant_id=$2::uuid AND reconciler=$4) FROM rss_reconcile.targets WHERE token IS NOT NULL")
        .bind(a.c.tenant.to_string()).bind(b.c.tenant.to_string()).bind(script::wake::scope(a.c.tenant).reconciler().to_owned())
        .bind(collection::wake::scope(b.c.tenant).reconciler().to_owned()).fetch_one(&a.c.operator)
    };
    let attempt = wait_for_blocked_attempt(&a.c.operator, pid, TaskOwner::Script.table()).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while counts().await?.0 != 7 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let collection = start_owner(a.a.collection_work.clone().registration(
        config.tasks,
        config.tasks_drain,
        Arc::default(),
    ))?;
    wait_for_blocked_attempt(&b.c.operator, peer_pid, TaskOwner::Collection.table()).await?;
    let peak = counts().await?;
    anyhow::ensure!(peak == (7, 1), "observed shared execution peak {peak:?}");
    eprintln!(
        "shared execution peak: Script {} + Collection {}",
        peak.0, peak.1
    );
    peer.rollback().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let done: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=$1::uuid AND input_consumed=input_revision AND runs_done")
                .bind(b.c.tenant.to_string()).fetch_one(&b.c.operator).await?;
            if done == 2 { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    anyhow::ensure!(
        blocked_attempt(&a.c.operator, pid, TaskOwner::Script.table()).await? == Some(attempt)
    );
    let drain = script.shutdown();
    let late = TaskOwner::Script.seed(&b).await?;
    notify.notify_one();
    held.rollback().await?;
    anyhow::ensure!(drain.join().await?.is_clean());
    let late_epoch: i64 = sqlx::query_scalar("SELECT epoch FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3")
        .bind(b.c.tenant.to_string()).bind(script::wake::scope(b.c.tenant).reconciler()).bind(format!("policy:{late}")).fetch_one(&b.c.operator).await?;
    anyhow::ensure!(late_epoch == 0, "new rows stay unclaimed after stop");
    let drained: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_script.policy_recovery WHERE tenant_id=$1::uuid AND input_consumed=input_revision AND runs_done")
        .bind(a.c.tenant.to_string()).fetch_one(&a.c.operator).await?;
    anyhow::ensure!(drained == 7);
    anyhow::ensure!(collection.shutdown().join().await?.is_clean());
    b.close().await?;
    a.close().await
}

#[tokio::test]
#[ignore = "T2: two slow settlements from A leave a real PostgreSQL scheduler connection for B"]
async fn scheduler_connections_remain_available_to_a_late_tenant() -> Result<()> {
    use crate::authority_t2_support::{blocked_attempt, wait_for_blocked_attempt};
    use rss_reconcile::{Completion, ResourceSet, Scope, Target};
    let a = Harness::open().await?;
    let b = Context::open("shared", &[]).await?;
    let store = a.a.resources.storage.reconcile.clone();
    anyhow::ensure!(
        a.a.resources
            .storage
            .read_pool
            .options()
            .get_max_connections()
            == 2
    );
    let timer = rss_mdm_policy_service::clock::Timer::new();
    let stop = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &stop);
    let scope_a = Scope::new(a.c.tenant, "mdm.test-3210")?;
    let scope_b = Scope::new(b.tenant, "mdm.test-3210")?;
    for (scope, id) in [(&scope_a, "one"), (&scope_a, "two"), (&scope_b, "peer")] {
        store
            .wake(
                &Target::new(scope.clone(), id)?,
                &ResourceSet::empty(scope.tenant()),
                &control,
            )
            .await?;
    }
    let leases = store
        .claim_due(&scope_a, 2, 64, Duration::from_secs(30), &control)
        .await?
        .claims;
    anyhow::ensure!(leases.len() == 2);
    let mut held = a.c.operator.begin().await?;
    let pids:Vec<i32> = sqlx::query_scalar("SELECT pg_backend_pid() FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 FOR UPDATE")
        .bind(a.c.tenant.to_string()).bind(scope_a.reconciler()).fetch_all(&mut *held).await?;
    let first = store.finish(&leases[0], Completion::Converged, &control);
    let second = store.finish(&leases[1], Completion::Converged, &control);
    let verify = async {
        let original = wait_for_blocked_attempt(&a.c.operator, pids[0], "").await?;
        let claim = store
            .claim_due(&scope_b, 1, 64, Duration::from_secs(30), &control)
            .await?
            .claims
            .pop()
            .expect("peer claim");
        store
            .finish(&claim, Completion::Converged, &control)
            .await?;
        anyhow::ensure!(blocked_attempt(&a.c.operator, pids[0], "").await? == Some(original));
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))",
        )
        .bind(pids[0])
        .fetch_one(&a.c.operator)
        .await?;
        anyhow::ensure!(
            blocked == 1,
            "one A settlement waits outside the physical pool"
        );
        held.rollback().await?;
        Ok::<_, anyhow::Error>(())
    };
    let (one, two, checked) = tokio::join!(first, second, verify);
    checked?;
    one?;
    two?;
    b.close().await;
    a.close().await
}
