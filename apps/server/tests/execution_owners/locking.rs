//! Policy change and recovery use the real PostgreSQL wait graph and production wake adapter.
use super::*;
use rss_mdm_inventory_service::collection::execution as collection;
use rss_mdm_policy_service::inputs::ExecutionChanges;
use rss_reconcile::{DurableStore, ReconcileStep, Reconciler};
use rss_transactional_messaging_postgres::PgRuntime;
use std::{
    sync::atomic::{AtomicI32, Ordering},
    time::Duration,
};

#[derive(Default)]
struct Gate {
    ready: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    pid: AtomicI32,
}
async fn change(
    runtime: &Arc<PgRuntime>,
    tenant: rss_request_context::TenantId,
    policy: Uuid,
    collection: bool,
    gate: &Gate,
) -> Result<()> {
    let changes = super::super::policy_ports::Changes {
        reader: rss_mdm_policy_postgres::PolicyReader::bind(
            rss_mdm_install_support::StorageProfile::Mdm,
            runtime.clone(),
            tenant,
        ),
        messaging: rss_reconcile_postgres::PgMessagingStore::new(
            runtime.clone(),
            tenant,
            script::transaction::deadline(),
        )
        .await?,
        targets: Arc::new(rss_mdm_scope_service::channels::ChannelTargets::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            Some(Arc::new(rss_mdm_device_service::planning::PlanningObjects)),
        )),
    };
    script::transaction::inspect(runtime,tenant,(changes,gate),move |ctx,tx|Box::pin(async move {
        let tenant=tx.tenant_id().to_string();
        let pid=tx.with_connection(move |c|Box::pin(async move {
            // The management writer owns the Policy row before enqueue_change_in calls Changes.
            sqlx::query("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
                .bind(&tenant).bind(policy).execute(&mut *c).await?;
            sqlx::query(if collection {
                "SELECT policy FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE"
            } else {
                "SELECT policy FROM mdm_script.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2 FOR UPDATE"
            }).bind(tenant).bind(policy).execute(&mut *c).await?;
            sqlx::query_scalar::<_,i32>("SELECT pg_backend_pid()").fetch_one(c).await
        })).await?;
        ctx.1.pid.store(pid,Ordering::Release);
        ctx.1.ready.notify_one();
        ctx.1.resume.notified().await;
        let current=script::transaction::checked(ctx.0.reader.locked_in(tx,policy).await?)?.expect("policy");
        script::transaction::checked(ctx.0.policy_changed_in(tx,&current,None).await)?;
        Ok(())
    })).await?;
    Ok(())
}
async fn wait_until_blocked(h: &Harness, gate: &Gate) -> Result<()> {
    let waiting=tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))")
                .bind(gate.pid.load(Ordering::Acquire)).fetch_one(&h.c.operator).await?;
            if blocked { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await;
    gate.resume.notify_one();
    waiting??;
    Ok(())
}
async fn recover_while_change_locked<T: rss_reconcile::Timer>(
    h: &Harness,
    collection: bool,
    claim: &rss_reconcile_postgres::PgClaim,
    diff: rss_reconcile::ReconcileDiff<bool>,
    control: &rss_reconcile::Control<'_, T>,
    gate: &Gate,
) -> Result<()> {
    gate.ready.notified().await;
    let apply = async {
        if collection {
            h.a.collection_work.apply(claim, diff, control).await
        } else {
            h.a.script_work.apply(claim, diff, control).await
        }
    };
    let (applied, unblocked) = futures::future::join(apply, wait_until_blocked(h, gate)).await;
    unblocked?;
    anyhow::ensure!(
        matches!(applied, Ok(ReconcileStep::Ready(()))),
        "policy recovery: {applied:?}"
    );
    Ok::<_, anyhow::Error>(())
}
async fn observe<T: rss_reconcile::Timer>(
    h: &Harness,
    collection: bool,
    claim: &rss_reconcile_postgres::PgClaim,
    control: &rss_reconcile::Control<'_, T>,
) -> Result<rss_reconcile::ReconcileDiff<bool>> {
    let diff = if collection {
        h.a.collection_work.observe(claim, control).await?
    } else {
        h.a.script_work.observe(claim, control).await?
    };
    let ReconcileStep::Ready(diff) = diff else {
        anyhow::bail!("policy observation deferred")
    };
    Ok(diff)
}
async fn claim_policy<T: rss_reconcile::Timer>(
    h: &Harness,
    collection: bool,
    control: &rss_reconcile::Control<'_, T>,
) -> Result<(
    rss_reconcile_postgres::PgStore,
    rss_reconcile_postgres::PgClaim,
    rss_reconcile::ReconcileDiff<bool>,
)> {
    let store =
        rss_reconcile_postgres::PgStore::new(h.a.resources.storage.read_pool.clone(), control)
            .await?;
    let scope = if collection {
        collection::wake::scope(h.c.tenant)
    } else {
        script::wake::scope(h.c.tenant)
    };
    let mut batch = store
        .claim_due(&scope, 1, Duration::from_secs(30), control)
        .await?;
    assert_eq!(batch.claims.len(), 1);
    let claim = batch.claims.remove(0);
    let diff = observe(h, collection, &claim, control).await?;
    Ok((store, claim, diff))
}
async fn policy_change_race(collection: bool) -> Result<()> {
    let h = Harness::open().await?;
    let policy = if collection {
        super::retirement::native(&h, None).await?.0
    } else {
        h.policy("policy-lock-order").await?.0
    };
    super::workers::wake(&h, collection, policy).await?;
    let runtime = crate::identity::open_runtime(
        &h.c.inputs.database("shared", "mdm_policy_runtime"),
        &h.c.inputs.installation.target,
        &h.c.inputs.installation.lineage,
        &[(h.c.tenant, 1)],
        2,
    )
    .await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &cancel);
    let (store, claim, diff) = claim_policy(&h, collection, &control).await?;
    let gate = Gate::default();
    let worker = recover_while_change_locked(&h, collection, &claim, diff, &control, &gate);
    let (changed, applied) = tokio::time::timeout(
        Duration::from_secs(15),
        futures::future::join(
            change(&runtime, h.c.tenant, policy, collection, &gate),
            worker,
        ),
    )
    .await?;
    changed?;
    applied?;
    let revisions:(i64,i64)=sqlx::query_as(if collection {
        "SELECT input_revision,input_consumed FROM mdm_inventory.collection_policy_recovery WHERE tenant_id=$1::uuid AND policy=$2"
    } else {
        "SELECT input_revision,input_consumed FROM mdm_script.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2"
    }).bind(h.c.tenant.to_string()).bind(policy).fetch_one(&h.c.operator).await?;
    assert_eq!(
        revisions,
        (2, 2),
        "the prepared snapshot must include the committed management wake"
    );
    store.release(&claim, &control).await?;
    runtime.close().await;
    h.close().await
}
#[tokio::test]
#[ignore = "T2: Script Policy recovery waits for management business locks before protecting its claim"]
async fn script_policy_change_and_worker_share_lock_order() -> Result<()> {
    policy_change_race(false).await
}
#[tokio::test]
#[ignore = "T2: Collection Policy recovery waits for management business locks before protecting its claim"]
async fn collection_policy_change_and_worker_share_lock_order() -> Result<()> {
    policy_change_race(true).await
}
