use super::frozen::Frozen;
use super::*;
use rss_mdm_policy::Policy;
pub async fn read_in(
    reader: &rss_mdm_policy_postgres::PolicyReader,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
) -> Result<Option<Policy>> {
    checked(reader.locked_in(tx, id).await?)
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
    source: &std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    tx: &mut PgTransaction<'_>,
    scope: Uuid,
    channel: rss_mdm_inventory::Channel,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<rss_mdm_scope_service::channels::ScopeAdmission> {
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
    source: &std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Option<i64>> {
    execution_eligible_in(
        source,
        tx,
        policy,
        policy.version,
        rss_mdm_inventory::Channel::Mdm,
        device,
    )
    .await
}

pub async fn execution_eligible_in(
    source: &std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
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
            rss_mdm_scope_service::channels::ScopeAdmission::Eligible { entry } => Some(entry),
            _ => None,
        },
    )
}
pub async fn withdrawn_in(
    source: &std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    tx: &mut PgTransaction<'_>,
    policy: &Policy,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<bool> {
    Ok(!policy.state.is_enabled()
        || admission_in(
            source,
            tx,
            policy.definition.scope,
            rss_mdm_inventory::Channel::Mdm,
            device,
        )
        .await?
            == rss_mdm_scope_service::channels::ScopeAdmission::Excluded)
}
