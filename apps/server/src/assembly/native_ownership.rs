//! Exactly-one business ownership, independent of current authorization or native progress.
use rss_mdm_policy_service::{
    Error, Failure,
    transaction::{Fault, Result},
};
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgTransaction;
use uuid::Uuid;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Owner {
    Configuration,
    Execution,
}
pub(super) async fn on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> std::result::Result<Owner, Error> {
    let owners = batch_on(c, tenant, &[id]).await?;
    owners.get(&id).copied().ok_or(Error::NotFound)
}
pub(super) async fn batch_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
) -> std::result::Result<std::collections::BTreeMap<Uuid, Owner>, Error> {
    if ids.len() > 1000 {
        return Err(Error::Malformed);
    }
    let configuration =
        rss_mdm_policy_service::configuration::storage::owned_ids_on(c, tenant, ids)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
    let execution = rss_mdm_execution_service::storage::owned_ids_on(c, tenant, ids)
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    ids.iter()
        .map(
            |id| match (configuration.contains(id), execution.contains(id)) {
                (true, false) => Ok((*id, Owner::Configuration)),
                (false, true) => Ok((*id, Owner::Execution)),
                (false, false) => Err(Error::NotFound),
                (true, true) => Err(Error::Unavailable(Failure::CommandInvariant)),
            },
        )
        .collect()
}

pub(super) async fn in_transaction(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Owner> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| Box::pin(async move { Ok(on(c, tenant, id).await) }))
        .await?
        .map_err(Fault::from)
}
