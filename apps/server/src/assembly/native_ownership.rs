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
    Software,
    Registration,
    Recovery,
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
    let software = rss_mdm_software_service::deployment::storage::owned_ids_on(c, tenant, ids)
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    let registration =
        rss_mdm_registration_service::installation::storage::owned_ids_on(c, tenant, ids)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
    let recovery = rss_mdm_recovery_credentials::native::storage::owned_ids_on(c, tenant, ids)
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    ids.iter()
        .map(|id| {
            let owners = [
                (configuration.contains(id), Owner::Configuration),
                (execution.contains(id), Owner::Execution),
                (software.contains(id), Owner::Software),
                (registration.contains(id), Owner::Registration),
                (recovery.contains(id), Owner::Recovery),
            ];
            let selected = owners
                .into_iter()
                .filter_map(|(present, owner)| present.then_some(owner))
                .collect::<Vec<_>>();
            match selected.as_slice() {
                [owner] => Ok((*id, *owner)),
                [] => Err(Error::NotFound),
                _ => Err(Error::Unavailable(Failure::CommandInvariant)),
            }
        })
        .collect()
}

pub(super) async fn in_transaction(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Owner> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| Box::pin(async move { Ok(on(c, tenant, id).await) }))
        .await?
        .map_err(Fault::from)
}
