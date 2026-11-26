//! Every real native command consumer ignores another owner and rejects its own orphan.
mod faults;
mod owners;
mod sql;
use super::*;
use rss_reconcile::{DurableStore, ReconcileStep, Reconciler};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
async fn claim_device(
    h: &Harness,
    scope: rss_reconcile::Scope,
    device: &rss_mdm_agent_wire::DeviceId,
    control: &rss_reconcile::Control<'_, rss_mdm_device_service::control::recovery::Timer>,
) -> Result<rss_reconcile_postgres::PgClaim> {
    let store = &h.a.resources.storage.reconcile;
    let target = rss_reconcile::Target::new(
        scope,
        format!("{:x}", Sha256::digest(device.to_string().as_bytes())),
    )?;
    store
        .wake(
            &target,
            &rss_mdm_registration_service::lifecycle::resources::device(
                h.c.tenant,
                device,
                rss_mdm_registration_service::lifecycle::resources::Work::Exclusive,
            ),
            control,
        )
        .await?;
    let mut claims = store
        .claim_due(target.scope(), 64, 64, Duration::from_secs(30), control)
        .await?
        .claims;
    let index = claims
        .iter()
        .position(|c| c.target() == &target)
        .expect("device claim");
    Ok(claims.swap_remove(index))
}
async fn control_page(
    h: &Harness,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<rss_reconcile::DriftKind> {
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &cancel);
    let claim = claim_device(
        h,
        rss_mdm_device_service::control::recovery_scope(h.c.tenant),
        device,
        &control,
    )
    .await?;
    let store = &h.a.resources.storage.reconcile;
    let ReconcileStep::Ready(diff) = h.a.service.observe(&claim, &control).await? else {
        anyhow::bail!("deferred observation")
    };
    let drift = diff.drift();
    let applied = if drift == rss_reconcile::DriftKind::Converged {
        Ok(ReconcileStep::Ready(()))
    } else {
        h.a.service.apply(&claim, diff, &control).await
    };
    store.release(&claim, &control).await?;
    assert!(matches!(applied?, ReconcileStep::Ready(())));
    Ok(drift)
}
#[tokio::test]
#[ignore = "T2: a real command owner processes only 64 legal candidates, resumes its text cursor after reconstruction, and rejects a later-page orphan atomically"]
async fn legal_candidates_page_across_restart_and_late_orphans() -> Result<()> {
    let mut h = Harness::open().await?;
    let native = super::retirement::native_controls(&mut h, 65).await?;
    let first = Uuid::from_u128(1).to_string();
    let last = Uuid::from_u128(65);
    let mut tx = command::seed_transaction(&h.c).await?;
    // Include an already-observed live command with unchanged version, and 64 terminal
    // commands not yet observed by the owner. No worker or notification receiver is running.
    sqlx::query("UPDATE rss_device_command.commands AS d SET status = 'cancelled', version = version + 1, terminal_at = queued_at + 1 FROM mdm_devices.control_operations AS o WHERE (o.tenant_id, CAST(o.id AS text)) = (d.tenant_id, d.command_id) AND o.tenant_id = CAST($1 AS uuid) AND o.device = $2 AND o.id <> $3").bind(h.c.tenant.to_string()).bind(native.device.into_uuid()).bind(Uuid::from_u128(1)).execute(&mut *tx).await?;
    let foreign_version: i64 = sqlx::query_scalar("INSERT INTO rss_device_command.commands SELECT tenant_id,'foreign-owner',device_id,generation,authority_epoch,expected_digest,deadline,queued_at,'another.owner.v1','foreign-owner',outbox_fingerprint,status,version,published_at,received_at,terminal_at FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2 RETURNING version")
        .bind(h.c.tenant.to_string()).bind(&first).fetch_one(&mut *tx).await?;
    // A non-UUID text ID after all legal IDs must not be silently skipped by cursor decoding.
    sqlx::query("INSERT INTO rss_device_command.commands SELECT tenant_id,'zz-orphan',device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,'zz-orphan',outbox_fingerprint,status,version,published_at,received_at,terminal_at FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2").bind(h.c.tenant.to_string()).bind(&first).execute(&mut *tx).await?;
    tx.commit().await?;
    sql::provider(&h, native.device).await?;
    sql::unknown_page(&h, &native.device).await?;
    let (observed,cursor):(i64,Option<String>)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND device=$2 AND observed_command_version>1),recovery_after FROM mdm_devices.control_recovery WHERE tenant_id=$1::uuid AND device=$2").bind(h.c.tenant.to_string()).bind(native.device.into_uuid()).fetch_one(&h.c.operator).await?;
    assert_eq!(
        observed, 63,
        "the unchanged live first command still occupies one candidate slot"
    );
    assert_eq!(cursor, Some(Uuid::from_u128(64).to_string()));
    let replacement = Fixture::open(&h.c).await?;
    Fixture::close(std::mem::replace(&mut h.a, replacement)).await?;
    assert!(control_page(&h, &native.device).await.is_err());
    let still_unobserved:i64=sqlx::query_scalar("SELECT observed_command_version FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(last).fetch_one(&h.c.operator).await?;
    assert_eq!(
        still_unobserved, 1,
        "the later-page orphan rolls back its complete owner page"
    );
    let unchanged:Option<String>=sqlx::query_scalar("SELECT recovery_after FROM mdm_devices.control_recovery WHERE tenant_id=$1::uuid AND device=$2").bind(h.c.tenant.to_string()).bind(native.device.into_uuid()).fetch_one(&h.c.operator).await?;
    assert_eq!(unchanged, cursor);
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("DELETE FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id='zz-orphan'").bind(h.c.tenant.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    control_page(&h, &native.device).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("UPDATE rss_device_command.commands SET status='cancelled',version=version+1,terminal_at=queued_at+1 WHERE tenant_id=$1::uuid AND command_id=$2").bind(h.c.tenant.to_string()).bind(&first).execute(&mut *tx).await?;
    tx.commit().await?;
    control_page(&h, &native.device).await?;
    assert_eq!(
        control_page(&h, &native.device).await?,
        rss_reconcile::DriftKind::Converged
    );
    let observed:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND device=$2 AND observed_command_version>1").bind(h.c.tenant.to_string()).bind(native.device.into_uuid()).fetch_one(&h.c.operator).await?;
    assert_eq!(observed, 65);
    for n in 1..=65 {
        assert!(
            faults::fact(&h.c, Uuid::from_u128(n), 2).await?.is_some(),
            "missing recovery fact for {n}"
        );
    }
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT version FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id='foreign-owner'")
        .bind(h.c.tenant.to_string()).fetch_one(&h.c.operator).await?, foreign_version);
    h.close().await
}

#[tokio::test]
#[ignore = "T2: the installed command runtime supersedes multiple pages in the product transaction"]
async fn command_generation_and_product_observation_settle_together() -> Result<()> {
    use rss_device_command::{BatchLimit, Coordinate, Scope, Store};
    use rss_transactional_messaging::policy::OperationDeadline;
    let mut h = Harness::open().await?;
    let native = super::retirement::native_controls(&mut h, 3).await?;
    let tenant = h.c.tenant;
    let command_device: Uuid = sqlx::query_scalar(
        "SELECT command_device FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2"
    ).bind(tenant.to_string()).bind(native.device.into_uuid()).fetch_one(&h.c.operator).await?;
    let scope = Scope::new(
        tenant,
        rss_device_command::DeviceId::parse(&command_device.to_string())?,
    );
    let state = || {
        sqlx::query_as::<_, (i64,i64,i64)>(
        "SELECT a.generation, (SELECT count(*) FROM rss_device_command.commands c WHERE c.tenant_id=a.tenant_id AND c.device_id=a.device_id AND c.status='superseded'),
        (SELECT observed_command_version FROM mdm_devices.control_operations WHERE tenant_id=a.tenant_id AND id=$3)
        FROM rss_device_command.authorities a WHERE tenant_id=$1::uuid AND device_id=$2"
    ).bind(tenant.to_string()).bind(command_device).bind(Uuid::from_u128(1)).fetch_one(&h.c.operator)
    };
    let before = state().await?;
    assert_eq!((before.0, before.1), (1, 0));
    for commit in [false, true] {
        let caller = h.a.resources.storage.runtime.clone();
        let (applied, observed) = tokio::sync::oneshot::channel();
        let page = BatchLimit::new(1)?;
        let old = Coordinate::new(1, 1)?;
        let next = Coordinate::new(2, 2)?;
        let outcome = caller.clone().local_tx(h.c.execution(), OperationDeadline::from_remaining(Duration::from_secs(10)), move |tx| Box::pin(async move {
            let (_,store) = crate::assembly::host_storage::bind_command_in(caller, tx,
                rss_device_command_postgres::CommandClock::Postgres, page, rss_mdm_device_service::control::messaging_domain()).await?;
            store.advance(tx, scope, old, next).await?;
            let rows = tx.with_connection(move |c| Box::pin(async move {
                Ok(sqlx::query("UPDATE mdm_devices.control_operations SET observed_command_version=observed_command_version+1 WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(tenant.to_string()).bind(Uuid::from_u128(1)).execute(c).await?.rows_affected())
            })).await?;
            let _ = applied.send(rows);
            if !commit { return Err(sqlx::Error::Protocol("interrupt after generation and product write".into()).into()); }
            Ok(())
        })).await;
        assert_eq!(observed.await?, 1);
        let committed = outcome.fold(|()| Ok(true), Err, |_| Ok(false), Err, Err, Err)?;
        assert_eq!(committed, commit);
        assert_eq!(
            state().await?,
            if commit { (2, 3, before.2 + 1) } else { before }
        );
    }
    h.close().await
}

async fn native_cursor(
    h: &Harness,
    table: &str,
    credentials: bool,
) -> Result<(
    rss_reconcile::Target,
    rss_reconcile::ResourceSet,
    rss_mdm_agent_wire::DeviceId,
)> {
    use rss_mdm_registration_service::lifecycle::resources;
    let device = crate::native_identity_t2_support::seed(&h.c, "windows")
        .await?
        .device;
    let command_device = Uuid::new_v4();
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_access.command_authorities(tenant_id,device,command_device,generation,epoch) VALUES($1::uuid,$2,$3,1,1)")
            .bind(h.c.tenant.to_string()).bind(device.into_uuid()).bind(command_device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1::uuid,$2,1,1)")
            .bind(h.c.tenant.to_string()).bind(command_device).execute(&mut *tx).await?;
    // The durable cursor models a restart after the last non-empty command page.
    sqlx::query(sqlx::AssertSqlSafe(format!("INSERT INTO {table}(tenant_id,device,expected_epoch,authority_epoch,recovery_after) VALUES($1::uuid,$2,$3,1,$4)")))
            .bind(h.c.tenant.to_string()).bind(device.into_uuid()).bind(h.c.execution().epoch().get()).bind(Uuid::new_v4().to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    let target = if credentials {
        rss_mdm_recovery_credentials::native::target(h.c.tenant, &device)
    } else {
        rss_mdm_registration_service::installation::target(h.c.tenant, &device)
    };
    Ok((
        target,
        resources::device(h.c.tenant, &device, resources::Work::Exclusive),
        device,
    ))
}

#[expect(
    clippy::cognitive_complexity,
    reason = "one transaction holds the original attempt through peer admission, receipt and worker shutdown"
)]
async fn native_cursor_isolation(credentials: bool) -> Result<()> {
    use crate::authority_t2_support::{blocked_attempt, wait_for_blocked_attempt};
    use rss_reconcile::DurableStore;
    use std::time::Duration;
    let a = Harness::open().await?;
    let b = Harness::open().await?;
    let table = if credentials {
        "mdm_recovery_tasks.device_recovery"
    } else {
        "mdm_registration_tasks.device_recovery"
    };
    let work = [
        native_cursor(&a, table, credentials).await?,
        native_cursor(&b, table, credentials).await?,
    ];
    let state = &a.a.resources;
    let notify = Arc::new(tokio::sync::Notify::new());
    let handles = [Arc::default(), notify.clone()];
    let registration = if credentials {
        let assembly = crate::assembly::credential_execution::assemble(
            state.storage.discovery_pool.clone(),
            &state.config,
            &state.background,
            state.storage.runtime.clone(),
            a.c.execution(),
            state.storage.audit.clone(),
            state.protection.clone(),
            crate::assembly::credential_owners_t2::protection(&a.c, "old")?,
            state.source.clone(),
            state.storage.reconcile.clone(),
            state.storage.worker_budget.clone(),
        )
        .await?;
        assembly.native.registration(
            state.background.commands,
            state.background.commands_drain,
            Arc::new(
                rss_mdm_recovery_credentials::native::worker_wake::Signals::from_handles(handles),
            ),
        )
    } else {
        a.a.registration.native.clone().registration(
            state.background.commands,
            state.background.commands_drain,
            Arc::new(
                rss_mdm_registration_service::installation::worker_wake::Signals::from_handles(
                    handles,
                ),
            ),
        )
    };
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(60), &cancel);
    let store = &state.storage.reconcile;
    let mut held = a.c.operator.begin().await?;
    let pid = sqlx::query_scalar("SELECT pg_backend_pid() FROM mdm_access.command_authorities WHERE tenant_id=$1::uuid AND device=$2 FOR UPDATE")
    .bind(a.c.tenant.to_string())
    .bind(work[0].2.into_uuid())
    .fetch_one(&mut *held)
    .await?;
    store.wake(&work[0].0, &work[0].1, &control).await?;
    let mut stack = rss_runtime::ShutdownStack::try_new(
        rss_runtime::TotalDrainBudget::new(Duration::from_secs(25))?,
        Arc::new(crate::lifecycle::RuntimeTimer),
    )?;
    let mut launch = stack.startup()?.commit();
    launch.stage_deferred_task_with_token(registration.critical());
    launch.finish();
    let check = tokio::time::timeout(Duration::from_secs(30), async {
        let attempt = wait_for_blocked_attempt(&a.c.operator, pid, "command_authorities").await?;
        store.wake(&work[1].0, &work[1].1, &control).await?;
        notify.notify_one();
        let receipt = format!(
            "SELECT recovery_after IS NULL FROM {table} WHERE tenant_id=$1::uuid AND device=$2"
        );
        while !sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(receipt.as_str()))
            .bind(b.c.tenant.to_string())
            .bind(work[1].2.into_uuid())
            .fetch_one(&b.c.operator)
            .await?
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::ensure!(
            blocked_attempt(&a.c.operator, pid, "command_authorities").await? == Some(attempt)
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    if !matches!(&check, Ok(Ok(()))) {
        for (h, target) in [(&a, &work[0].0), (&b, &work[1].0)] {
            let state: Option<(i64,String,i64)> = sqlx::query_as("SELECT epoch,result,failures FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3")
                .bind(h.c.tenant.to_string()).bind(target.scope().reconciler()).bind(target.entity()).fetch_optional(&h.c.operator).await?;
            eprintln!("{table} tenant {} RSS state {state:?}", h.c.tenant);
        }
    }
    held.rollback().await?;
    anyhow::ensure!(stack.shutdown().join().await?.is_clean());
    b.close().await?;
    a.close().await?;
    check?
}
#[tokio::test]
#[ignore = "T2: an installation cursor commits while another tenant cannot finish its native recovery page"]
async fn registration_native_cursor_isolation() -> Result<()> {
    native_cursor_isolation(false).await
}
#[tokio::test]
#[ignore = "T2: a native credentials cursor commits during a peer's locked page"]
async fn credentials_native_cursor_isolation() -> Result<()> {
    native_cursor_isolation(true).await
}
