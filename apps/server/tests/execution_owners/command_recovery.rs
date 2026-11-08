//! Every real native command consumer ignores another owner and rejects its own orphan.
use super::*;
use rss_reconcile::{DurableStore, ReconcileStep, Reconciler};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
async fn candidate(h: &Harness, domain: &str) -> Result<(String, Uuid)> {
    let object = planning::endpoint(&h.c).await?;
    let target = &object.members[0];
    let id = Uuid::new_v4();
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1::uuid,$2,1,1)").bind(h.c.tenant.to_string()).bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.command_authorities (tenant_id, device, command_device, generation, epoch) VALUES (CAST($1 AS uuid), $2, $3, 1, 1)").bind(h.c.tenant.to_string()).bind(&target.device).bind(id).execute(&mut *tx).await?;
    // Text IDs intentionally do not parse as UUID. The unrelated expired command must be untouched.
    sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) VALUES($1::uuid,$2,$3,1,1,$4,2000000,1000000,$5,$2,$4,'published',1000000,2)")
        .bind(h.c.tenant.to_string()).bind(format!("foreign:{id}" )).bind(id).bind(vec![1u8;32]).bind(domain).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((target.device.clone(), id))
}
async fn claim_device(
    h: &Harness,
    scope: rss_reconcile::Scope,
    device: &str,
    control: &rss_reconcile::Control<'_, rss_mdm_device_service::control::recovery::Timer>,
) -> Result<rss_reconcile_postgres::PgClaim> {
    let store = &h.a.resources.storage.reconcile;
    let target =
        rss_reconcile::Target::new(scope, format!("{:x}", Sha256::digest(device.as_bytes())))?;
    store
        .wake(
            &target,
            &rss_reconcile::ResourceSet::empty(h.c.tenant),
            control,
        )
        .await?;
    let mut claims = store
        .claim_due(target.scope(), 64, Duration::from_secs(30), control)
        .await?
        .claims;
    let index = claims
        .iter()
        .position(|c| c.target() == &target)
        .expect("device claim");
    Ok(claims.swap_remove(index))
}
async fn prove<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
    h: &Harness,
    worker: &R,
    scope: rss_reconcile::Scope,
    domain: &str,
) -> Result<()> {
    let (device, id) = candidate(h, "another.owner.v1").await?;
    let timer = rss_mdm_device_service::control::recovery::Timer::new();
    let cancel = CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, Duration::from_secs(20), &cancel);
    let claim = claim_device(h, scope, &device, &control).await?;
    let ReconcileStep::Ready(diff) = worker.observe(&claim, &control).await? else {
        anyhow::bail!("unexpected observation deferral")
    };
    assert_eq!(diff.drift(), rss_reconcile::DriftKind::Converged);
    assert!(matches!(
        worker.apply(&claim, diff, &control).await?,
        ReconcileStep::Ready(())
    ));
    let version:i64=sqlx::query_scalar("SELECT version FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2").bind(h.c.tenant.to_string()).bind(format!("foreign:{id}")).fetch_one(&h.c.operator).await?;
    assert_eq!(version, 2);
    assert_orphan_rejected(h, worker, &claim, &control, id, domain).await
}
async fn assert_orphan_rejected<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
    h: &Harness,
    worker: &R,
    claim: &rss_reconcile_postgres::PgClaim,
    control: &rss_reconcile::Control<'_, rss_mdm_device_service::control::recovery::Timer>,
    id: Uuid,
    domain: &str,
) -> Result<()> {
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO rss_device_command.commands SELECT tenant_id,$3,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,$4,$3,outbox_fingerprint,status,version,published_at,received_at,terminal_at FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2")
        .bind(h.c.tenant.to_string()).bind(format!("foreign:{id}")).bind(format!("orphan:{id}")).bind(domain).execute(&mut *tx).await?;
    tx.commit().await?;
    let ReconcileStep::Ready(diff) = worker.observe(claim, control).await? else {
        anyhow::bail!("unexpected orphan deferral")
    };
    assert_ne!(diff.drift(), rss_reconcile::DriftKind::Converged);
    assert!(worker.apply(claim, diff, control).await.is_err());
    let versions:Vec<i64>=sqlx::query_scalar("SELECT version FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND device_id=$2 ORDER BY command_id COLLATE \"C\"").bind(h.c.tenant.to_string()).bind(id).fetch_all(&h.c.operator).await?;
    assert_eq!(versions, vec![2, 2]);
    Ok(())
}
#[tokio::test]
#[ignore = "T2: four concrete native command owners isolate candidate domains and reject reverse orphans without repairing or advancing either command"]
async fn native_consumers_never_recover_another_owners_commands() -> Result<()> {
    let h = Harness::open().await?;
    prove(
        &h,
        h.a.software.service.as_ref(),
        rss_mdm_software_service::deployment::recovery_scope(h.c.tenant),
        rss_mdm_software_service::deployment::messaging_domain().as_str(),
    )
    .await?;
    prove(
        &h,
        h.a.service.as_ref(),
        rss_mdm_device_service::control::recovery_scope(h.c.tenant),
        rss_mdm_device_service::control::messaging_domain().as_str(),
    )
    .await?;
    prove(
        &h,
        h.a.registration.native.as_ref(),
        rss_mdm_registration_service::installation::recovery_scope(h.c.tenant),
        rss_mdm_registration_service::installation::messaging_domain().as_str(),
    )
    .await?;
    let resources = &h.a.resources;
    let credentials = super::super::credential_owners_t2::protection(&h.c, "new")?;
    let native = super::super::credential_execution::assemble(
        &resources.config,
        resources.storage.runtime.clone(),
        h.c.tenant,
        resources.storage.audit.clone(),
        resources.protection.clone(),
        credentials,
        resources.source.clone(),
        resources.storage.reconcile.clone(),
        resources.storage.worker_budget.clone(),
    )
    .await?;
    prove(
        &h,
        native.native.as_ref(),
        rss_mdm_recovery_credentials::native::recovery_scope(h.c.tenant),
        rss_mdm_recovery_credentials::native::messaging_domain().as_str(),
    )
    .await?;
    drop(native);
    h.close().await
}

async fn control_page(h: &Harness, device: &str) -> Result<rss_reconcile::DriftKind> {
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
    sqlx::query("UPDATE rss_device_command.commands AS d SET status = 'cancelled', version = version + 1, terminal_at = queued_at + 1 FROM mdm_devices.control_operations AS o WHERE (o.tenant_id, CAST(o.id AS text)) = (d.tenant_id, d.command_id) AND o.tenant_id = CAST($1 AS uuid) AND o.device = $2 AND o.id <> $3").bind(h.c.tenant.to_string()).bind(native.device.clone()).bind(Uuid::from_u128(1)).execute(&mut *tx).await?;
    // A non-UUID text ID after all legal IDs must not be silently skipped by cursor decoding.
    sqlx::query("INSERT INTO rss_device_command.commands SELECT tenant_id,'zz-orphan',device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,'zz-orphan',outbox_fingerprint,status,version,published_at,received_at,terminal_at FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2").bind(h.c.tenant.to_string()).bind(&first).execute(&mut *tx).await?;
    tx.commit().await?;
    control_page(&h, &native.device).await?;
    let (observed,cursor):(i64,Option<String>)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND device=$2 AND observed_command_version>1),recovery_after FROM mdm_devices.control_recovery WHERE tenant_id=$1::uuid AND device=$2").bind(h.c.tenant.to_string()).bind(&native.device).fetch_one(&h.c.operator).await?;
    assert_eq!(
        observed, 63,
        "the unchanged live first command still occupies one candidate slot"
    );
    assert_eq!(cursor, Some(Uuid::from_u128(64).to_string()));
    let replacement = Fixture::open(&h.c, true).await?;
    Fixture::close(std::mem::replace(&mut h.a, replacement)).await?;
    assert!(control_page(&h, &native.device).await.is_err());
    let still_unobserved:i64=sqlx::query_scalar("SELECT observed_command_version FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND id=$2").bind(h.c.tenant.to_string()).bind(last).fetch_one(&h.c.operator).await?;
    assert_eq!(
        still_unobserved, 1,
        "the later-page orphan rolls back its complete owner page"
    );
    let unchanged:Option<String>=sqlx::query_scalar("SELECT recovery_after FROM mdm_devices.control_recovery WHERE tenant_id=$1::uuid AND device=$2").bind(h.c.tenant.to_string()).bind(&native.device).fetch_one(&h.c.operator).await?;
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
    let observed:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_devices.control_operations WHERE tenant_id=$1::uuid AND device=$2 AND observed_command_version>1").bind(h.c.tenant.to_string()).bind(&native.device).fetch_one(&h.c.operator).await?;
    assert_eq!(observed, 65);
    h.close().await
}
