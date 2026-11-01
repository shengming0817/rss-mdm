use super::*;
pub async fn lock(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    rss_mdm_policy_postgres::lock_coordination_in(tx, id).await?;
    Ok(())
}
pub async fn read_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Policy>> {
    checked(reader.locked_in(tx, id).await?)
}

pub async fn wake_execution_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_devices.unmanage_policy_recovery(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=mdm_devices.unmanage_policy_recovery.input_revision+1").bind(tenant).bind(policy).execute(c).await?;
        Ok(())
    })).await?;
    let target = rss_reconcile::Target::new(
        crate::control::recovery_scope(tx.tenant_id()),
        format!("policy.{policy}"),
    )
    .map_err(|_| Error::Malformed)?;
    reconcile
        .wake_in(
            tx,
            &target,
            &rss_reconcile::ResourceSet::empty(target.scope().tenant()),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    crate::control::worker_wake::notify_in(tx, crate::control::worker_wake::Work::CommandRecovery)
        .await?;
    Ok(())
}
pub async fn version_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<(Policy, Frozen)> {
    let version = checked(reader.version_in(tx, id).await?)?.ok_or(Error::NotFound)?;
    let owner = read_in(reader, tx, version.policy)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((owner, stored(serde_json::from_value(version.frozen))?))
}

/// Page reads use their caller's single snapshot without Policy write locks.
pub async fn read_on(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    c: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<Option<Policy>> {
    checked(reader.read_on(c, id).await?)
}
pub async fn version_on(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    c: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<(Policy, Frozen)> {
    let version = checked(reader.version_on(c, id).await?)?.ok_or(Error::NotFound)?;
    let owner = read_on(reader, c, version.policy)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((owner, stored(serde_json::from_value(version.frozen))?))
}
