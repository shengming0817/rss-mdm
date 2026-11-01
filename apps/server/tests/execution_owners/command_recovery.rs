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
    sqlx::query("INSERT INTO mdm_access.command_authorities(tenant_id,device,command_device,generation,epoch,registration,registration_generation) VALUES($1::uuid,$2,$3,1,1,$4,1)").bind(h.c.tenant.to_string()).bind(&target.device).bind(id).bind(target.registration_id).execute(&mut *tx).await?;
    // Text IDs intentionally do not parse as UUID. The unrelated expired command must be untouched.
    sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) VALUES($1::uuid,$2,$3,1,1,$4,2000000,1000000,$5,$2,$4,'published',1000000,2)")
        .bind(h.c.tenant.to_string()).bind(format!("foreign:{id}" )).bind(id).bind(vec![1u8;32]).bind(domain).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((target.device.clone(), id))
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
    let store = &h.a.resources.storage.reconcile;
    let target = rss_reconcile::Target::new(
        scope.clone(),
        format!("{:x}", Sha256::digest(device.as_bytes())),
    )?;
    store
        .wake(
            &target,
            &rss_reconcile::ResourceSet::empty(h.c.tenant),
            &control,
        )
        .await?;
    let mut claims = store
        .claim_due(&scope, 64, Duration::from_secs(30), &control)
        .await?
        .claims;
    let index = claims
        .iter()
        .position(|c| c.target() == &target)
        .expect("device claim");
    let claim = claims.swap_remove(index);
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
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO rss_device_command.commands SELECT tenant_id,$3,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,$4,$3,outbox_fingerprint,status,version,published_at,received_at,terminal_at FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2")
        .bind(h.c.tenant.to_string()).bind(format!("foreign:{id}")).bind(format!("orphan:{id}")).bind(domain).execute(&mut *tx).await?;
    tx.commit().await?;
    let ReconcileStep::Ready(diff) = worker.observe(&claim, &control).await? else {
        anyhow::bail!("unexpected orphan deferral")
    };
    assert_ne!(diff.drift(), rss_reconcile::DriftKind::Converged);
    assert!(worker.apply(&claim, diff, &control).await.is_err());
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
