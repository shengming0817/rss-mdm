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
    Device,
    Software,
    Registration,
    Recovery,
}
pub(super) async fn on_device(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    device: &rss_mdm_agent_wire::DeviceId,
    id: Uuid,
) -> std::result::Result<Owner, Error> {
    let owners = resolve(c, tenant, &[id], Some(device.into_uuid())).await?;
    owners.get(&id).copied().ok_or(Error::NotFound)
}

pub(super) async fn batch_on(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
) -> std::result::Result<std::collections::BTreeMap<Uuid, Owner>, Error> {
    resolve(c, tenant, ids, None).await
}

async fn resolve(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
    device: Option<Uuid>,
) -> std::result::Result<std::collections::BTreeMap<Uuid, Owner>, Error> {
    if ids.len() > 1000 {
        return Err(Error::Malformed);
    }
    let configuration =
        rss_mdm_policy_service::configuration::storage::owned_devices_on(c, tenant, ids)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
    let execution = rss_mdm_device_service::control::storage::owned_devices_on(c, tenant, ids)
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    let software = rss_mdm_software_service::deployment::storage::owned_devices_on(c, tenant, ids)
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    let registration =
        rss_mdm_registration_service::installation::storage::owned_devices_on(c, tenant, ids)
            .await
            .map_err(|_| Error::Unavailable(Failure::Database))?;
    let recovery = rss_mdm_recovery_credentials::native::storage::owned_devices_on(c, tenant, ids)
        .await
        .map_err(|_| Error::Unavailable(Failure::Database))?;
    ids.iter()
        .map(|id| {
            let owners = [
                (configuration.get(id), Owner::Configuration),
                (execution.get(id), Owner::Device),
                (software.get(id), Owner::Software),
                (registration.get(id), Owner::Registration),
                (recovery.get(id), Owner::Recovery),
            ];
            if let Some(device) = device
                && !owners.iter().any(|(target, _)| *target == Some(&device))
            {
                return Err(Error::NotFound);
            }
            let mut matches = owners
                .into_iter()
                .filter_map(|(target, owner)| target.map(|_| owner));
            let owner = matches.next().ok_or(Error::NotFound)?;
            if matches.next().is_some() {
                return Err(Error::Unavailable(Failure::CommandInvariant));
            }
            Ok((*id, owner))
        })
        .collect()
}

pub(super) async fn in_transaction(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Owner> {
    let tenant = tx.tenant_id();
    tx.with_connection(move |c| {
        Box::pin(async move {
            Ok(batch_on(c, tenant, &[id])
                .await
                .and_then(|owners| owners.get(&id).copied().ok_or(Error::NotFound)))
        })
    })
    .await?
    .map_err(Fault::from)
}
