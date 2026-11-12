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
        sqlx::query("INSERT INTO mdm_software_deployment.policy_recovery(tenant_id,policy) VALUES($1::uuid,$2) ON CONFLICT(tenant_id,policy) DO UPDATE SET input_revision=mdm_software_deployment.policy_recovery.input_revision+1").bind(tenant).bind(policy).execute(c).await?;
        Ok(())
    })).await?;
    wake_dispatch_in(reconcile, tx, policy).await
}
/// The caller has already advanced the gate dispatch revision in this transaction.
pub(crate) async fn wake_dispatch_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
) -> Result<()> {
    let target = rss_reconcile::Target::new(
        crate::deployment::recovery_scope(tx.tenant_id()),
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
    crate::deployment::worker_wake::notify_in(
        tx,
        crate::deployment::worker_wake::Work::CommandRecovery,
    )
    .await?;
    Ok(())
}
pub async fn version_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<(Policy, Published)> {
    let version = checked(reader.version_in(tx, id).await?)?.ok_or(Error::NotFound)?;
    let owner = read_in(reader, tx, version.policy)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((owner, stored(serde_json::from_value(version.frozen))?))
}

/// Scope facts are read with the original transaction's snapshot and locks.
pub async fn admission_in(
    source: &std::sync::Arc<dyn crate::deployment::scope::Sources>,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    channel: rss_mdm_inventory::Channel,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<crate::deployment::scope::ScopeAdmission> {
    let tenant = tx.tenant_id();
    let source = source.clone();
    let device = device.to_owned();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(source
                    .admission_on(c, tenant, scope, channel, &device)
                    .await)
            })
        })
        .await??)
}
pub async fn eligible_in(
    source: &std::sync::Arc<dyn crate::deployment::scope::Sources>,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Option<i64>> {
    execution_eligible_in(
        source,
        tx,
        policy,
        policy.version,
        crate::deployment::sources::candidates::action_channel(&policy.definition.action)?,
        device,
    )
    .await
}

pub async fn execution_eligible_in(
    source: &std::sync::Arc<dyn crate::deployment::scope::Sources>,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    _version: Uuid,
    channel: rss_mdm_inventory::Channel,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Option<i64>> {
    let tenant_name = tx.tenant_id().to_string();
    let device_name = device.to_owned();
    let allowed = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(rss_mdm_registration_service::lifecycle::work_allowed_in(
                    rss_mdm_install_support::StorageProfile::Mdm,
                    c,
                    &tenant_name,
                    &device_name,
                )
                .await)
            })
        })
        .await??;
    if !allowed {
        return Ok(None);
    }
    if !policy.state.is_enabled() {
        return Ok(None);
    }
    Ok(
        match admission_in(source, tx, policy.definition.scope, channel, device).await? {
            crate::deployment::scope::ScopeAdmission::Eligible { entry } => Some(entry),
            _ => None,
        },
    )
}
pub async fn withdrawn_in(
    source: &std::sync::Arc<dyn crate::deployment::scope::Sources>,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<bool> {
    Ok(!policy.state.is_enabled()
        || admission_in(
            source,
            tx,
            policy.definition.scope,
            crate::deployment::sources::candidates::action_channel(&policy.definition.action)?,
            device,
        )
        .await?
            == crate::deployment::scope::ScopeAdmission::Excluded)
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
) -> Result<(Policy, Published)> {
    let version = checked(reader.version_on(c, id).await?)?.ok_or(Error::NotFound)?;
    let owner = read_on(reader, c, version.policy)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((owner, stored(serde_json::from_value(version.frozen))?))
}
