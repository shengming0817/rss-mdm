use super::*;
pub async fn lock(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    crate::action_admission::lock(tx, &format!("policy:{id}")).await
}
pub async fn read_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Policy>> {
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT mdm_planning.policy_lock($1)")
                .bind(id)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await?;
    checked(reader.read_in(tx, id).await?)
}
pub async fn wake_execution_in(tx: &mut PgTransaction<'_>, policy: Uuid) -> Result<()> {
    let target = rss_reconcile::Target::new(
        crate::recovery_scope(tx.tenant_id()),
        format!("policy.{policy}"),
    )
    .map_err(|_| Error::Malformed)?;
    rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
        .await?;
    crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
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

/// Scope facts are read with the original transaction's snapshot and locks.
pub async fn admission_in(
    source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    channel: rss_mdm_inventory::Channel,
    device: &str,
) -> Result<crate::source_authority::ScopeAdmission> {
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
    source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    device: &str,
) -> Result<Option<i64>> {
    let reader = source.clone();
    let tenant = tx.tenant_id();
    let version = policy.version;
    let readable = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(reader.policy_readable_on(c, tenant, version).await) })
        })
        .await??;
    if !policy.enabled || !readable {
        return Ok(None);
    }
    Ok(
        match admission_in(
            source,
            tx,
            policy.definition.scope,
            crate::source_authority::action_channel(policy.definition.action.kind()),
            device,
        )
        .await?
        {
            crate::source_authority::ScopeAdmission::Eligible { entry } => {
                let tenant = tx.tenant_id().to_string();
                let id = policy.id;
                let version = policy.version;
                let device = device.to_owned();
                let channel =
                    crate::source_authority::action_channel(policy.definition.action.kind())
                        .as_str();
                let stable=tx.with_connection(move|c|Box::pin(async move {sqlx::query_scalar::<_,Option<i64>>("SELECT min(entry_revision) FROM mdm_planning.policy_assignments WHERE tenant_id=$1::uuid AND policy=$2 AND version=$3 AND channel=$4 AND target->>'device'=$5 AND entry_revision>0").bind(tenant).bind(id).bind(version).bind(channel).bind(device).fetch_one(c).await})).await?;
                Some(stable.unwrap_or(entry))
            }
            _ => None,
        },
    )
}
pub async fn withdrawn_in(
    source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    device: &str,
) -> Result<bool> {
    Ok(!policy.enabled
        || admission_in(
            source,
            tx,
            policy.definition.scope,
            crate::source_authority::action_channel(policy.definition.action.kind()),
            device,
        )
        .await?
            == crate::source_authority::ScopeAdmission::Excluded)
}

pub async fn readable_in(
    source: &std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    tx: &mut PgTransaction<'_>,
    version: Uuid,
) -> Result<bool> {
    let source = source.clone();
    let tenant = tx.tenant_id();
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(source.policy_readable_on(c, tenant, version).await) })
        })
        .await??)
}
