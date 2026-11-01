use super::*;
use rss_transactional_messaging_postgres::PgTransaction;
pub async fn capable_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    target: &Target,
    frozen: &FrozenEnrollment,
) -> Result<bool> {
    let Some(binding) =
        agent_facts::agent_binding_in(tx, service.agent_store.clone(), target.registration).await?
    else {
        return Ok(false);
    };
    if !binding.inventory() || !binding.enrollment() {
        return Ok(false);
    }
    let Some((platform, _)) = agent_facts::profile_in(service, tx, target.registration).await?
    else {
        return Ok(false);
    };
    if frozen.entries.for_platform(platform).is_none() {
        return Ok(false);
    }
    Ok(true)
}
pub async fn require_in(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    target: &Target,
    frozen: &FrozenEnrollment,
) -> Result<bool> {
    if !capable_in(service, tx, target, frozen).await? {
        return Ok(false);
    }
    let inventory = service.inventory.clone();
    let tenant = tx.tenant_id();
    let registration = target.registration;
    let generation = target.generation;
    Ok(
        matches!(tx.with_connection(move|c|Box::pin(async move {Ok(inventory.enrollment_on(c,tenant,registration,generation).await)})).await??,rss_mdm_inventory::channel::Observation::Ready(fact) if fact.state=="unenrolled"),
    )
}
