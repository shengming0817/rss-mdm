use super::*;
use rss_mdm_inventory_service::collection::execution as collection;
use rss_reconcile::DurableStore;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
fn policy() -> Result<rss_reconcile::Policy> {
    Ok(rss_reconcile::Policy::try_from(
        rss_reconcile::PolicyConfig {
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
    let messaging = rss_reconcile_postgres::PgMessagingStore::new(
        h.a.runtime.clone(),
        h.c.tenant,
        script::transaction::deadline(),
    )
    .await?;
    script::transaction::inspect(
        &h.a.runtime,
        h.c.tenant,
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
        super::mixed::run(h, version, true, now()).await?
    } else {
        h.run(version, "checkpoint", now() + 300).await?
    };
    let mut cancelled = rss_mdm_task_state::RunState::new(now() + 300, now())?;
    cancelled.cancel();
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query(if collection {"UPDATE mdm_inventory.collection_tasks SET agent_state=$3 WHERE tenant_id=$1::uuid AND id=$2"} else {"UPDATE mdm_script.runs SET state=$3 WHERE tenant_id=$1::uuid AND id=$2"}).bind(h.c.tenant.to_string()).bind(first).bind(serde_json::to_value(cancelled)?).execute(&mut *tx).await?;
    sqlx::query(if collection {"INSERT INTO mdm_inventory.collection_tasks(tenant_id,id,occurrence,policy_version,channel,origin,source_objects,device,registration,generation,created_at,available_at,deadline,agent_state,dispatch_fingerprint) SELECT tenant_id,gen_random_uuid(),'page:'||n,policy_version,channel,origin,source_objects,device,registration,generation,created_at,available_at,deadline,agent_state,dispatch_fingerprint FROM mdm_inventory.collection_tasks CROSS JOIN generate_series(1,32) n WHERE tenant_id=$1::uuid AND id=$2"} else {"INSERT INTO mdm_script.runs(tenant_id,id,occurrence,policy_version,resource_id,origin,source_objects,device,registration,generation,created_at,available_at,deadline,state,dispatch_fingerprint) SELECT tenant_id,gen_random_uuid(),'page:'||n,policy_version,resource_id,origin,source_objects,device,registration,generation,created_at,available_at,deadline,state,dispatch_fingerprint FROM mdm_script.runs CROSS JOIN generate_series(1,32) n WHERE tenant_id=$1::uuid AND id=$2"}).bind(h.c.tenant.to_string()).bind(first).execute(&mut *tx).await?;
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
    let timer = rss_mdm_execution_service::recovery::Timer::new();
    let force = CancellationToken::new();
    let stop = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &force);
    let store = rss_reconcile_postgres::PgStore::new(h.a.read_pool.clone(), &control).await?;
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
        h.a.collection_work.clone().registration(notify)
    } else {
        h.a.script_work.clone().registration(notify)
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
    let timer = rss_mdm_execution_service::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(6), &cancel);
    let store = rss_reconcile_postgres::PgStore::new(h.a.read_pool.clone(), &control).await?;
    assert!(
        store
            .claim_due(scope, 64, Duration::from_secs(30), &control)
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
    let a = command::open(&h.c, true).await?;
    let (audit, delivery) = super::delivery(&h.c, &a).await?;
    drop(std::mem::replace(&mut h.delivery, delivery));
    drop(std::mem::replace(&mut h.audit, audit));
    command::close(std::mem::replace(&mut h.a, a)).await?;
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
    let timer = rss_mdm_execution_service::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let stop = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &cancel);
    let store = rss_reconcile_postgres::PgStore::new(h.a.read_pool.clone(), &control).await?;
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
    let (_, task, _) = super::retirement::native(&h, None).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE mdm_access.collection_runs SET deadline=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND id=(SELECT collection_run FROM mdm_inventory.collection_tasks WHERE tenant_id=$1::uuid AND id=$2)")
        .bind(h.c.tenant.to_string()).bind(task).execute(&mut *tx).await?;
    tx.commit().await?;
    script::transaction::run(
        &h.audit,
        &h.a.runtime,
        h.c.tenant,
        &request(&h.c),
        &h,
        |h, tx| {
            Box::pin(async move {
                let tenant = tx.tenant_id().to_string();
                let (count, facts) = tx
                    .with_connection(move |c| {
                        Box::pin(async move {
                            let mut facts = Vec::new();
                            let count = rss_mdm_inventory_service::collection::store::expire_timed(
                                c, &mut facts, &tenant,
                            )
                            .await;
                            Ok((count, facts))
                        })
                    })
                    .await?;
                assert_eq!(count.map_err(script::Error::from)?, 1);
                h.audit.append_batch_in(tx, &facts).await?;
                Ok(())
            })
        },
    )
    .await?;
    assert_eq!(native_notifications(&h, task).await?, (false, 0, 0));
    // A failure after emitting must roll back both the event and completion receipt.
    let failed: std::result::Result<(), _> = script::transaction::run(
        &h.audit,
        &h.a.runtime,
        h.c.tenant,
        &request(&h.c),
        &h,
        |h, tx| {
            Box::pin(async move {
                collection::recovery::recover_one(&h.a.collections, tx, task).await?;
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
