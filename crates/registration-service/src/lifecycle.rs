use crate::Error;
use std::{future::Future, pin::Pin};
/// Participate after registration state is retired, using the same borrowed transaction.
pub trait Retirement: Send + Sync {
    /// The host's optional event destination, fixed with this lifecycle participant.
    fn events(&self) -> Option<&dyn crate::EventSink>;
    fn retire<'a>(
        &'a self,
        tx: &'a mut sqlx::PgConnection,
        facts: &'a mut Vec<rss_mdm_audit_integration::Fact>,
        tenant: &'a str,
        device: &'a str,
        state: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}
pub async fn retire(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
    device: &str,
    state: &str,
    participant: &dyn Retirement,
) -> Result<(), Error> {
    lock_device_in(profile, tx, tenant, device).await?;
    // Credentials and protocol requests close with their device in this transaction.
    crate::device::store::retire_state_in(profile, tx, tenant, device, state, participant.events())
        .await?;
    participant.retire(tx, facts, tenant, device, state).await
}

/// The product's single endpoint fence: registration, execution and all channels,
/// including enrollment which has no row yet. Held until transaction settlement.
/// ref: PostgreSQL src/backend/utils/adt/lockfuncs.c (transaction advisory locks).
/// Callers acquiring more than one endpoint lock must use lexical device order.
pub async fn lock_device_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<(), Error> {
    lock_devices_in(profile, c, tenant, &[device.to_owned()]).await
}
/// Acquire a page's endpoint fences in the same lexical order as single-device writers.
pub async fn lock_devices_in(
    _profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<(), Error> {
    let keys = device_lock_keys(tenant, devices)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(key,2790)) FROM unnest($1::text[]) WITH ORDINALITY locks(key,n) ORDER BY n").bind(keys).execute(c).await.map_err(crate::database::db)?;
    Ok(())
}

/// Try an endpoint page without waiting behind device writers while a caller holds directory locks.
/// A false result requires the caller to roll back the entire transaction before retrying.
pub async fn try_lock_devices_in(
    _profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<bool, Error> {
    for key in device_lock_keys(tenant, devices)? {
        let locked: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2790))")
                .bind(key)
                .fetch_one(&mut *c)
                .await
                .map_err(crate::database::db)?;
        if !locked {
            return Ok(false);
        }
    }
    Ok(true)
}
fn device_lock_keys(tenant: &str, devices: &[String]) -> Result<Vec<String>, Error> {
    if devices.len() > 1000 {
        return Err(Error::Malformed);
    }
    let keys = devices
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|device| serde_json::to_string(&(tenant, device)).map_err(|_| Error::Malformed))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(keys)
}

/// Normal work and enrollment cannot cross an accepted retirement. Authentication
/// remains separate so the exact cleanup operation can still receive its evidence.
pub async fn require_work_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<(), Error> {
    if !work_allowed_in(profile, c, tenant, device).await? {
        return Err(Error::Forbidden);
    }
    Ok(())
}

pub async fn work_allowed_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<bool, Error> {
    lock_device_in(profile, c, tenant, device).await?;
    work_allowed_on(profile, c, tenant, device).await
}

/// Read current retirement eligibility inside the caller's snapshot.
/// Execution writers retain the endpoint fence through work_allowed_in.
pub async fn work_allowed_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<bool, Error> {
    let exit: Option<uuid::Uuid> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).lifecycle_work_allowed_on_1)
            .bind(tenant)
            .bind(device)
            .fetch_optional(c)
            .await
            .map_err(crate::database::db)?
            .flatten();
    Ok(exit.is_none())
}

/// The lifecycle owner calls this in its original audited acceptance transaction.
/// Replays keep the first operation; competing policies cannot replace its authority.
pub async fn begin_retirement_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    operation: uuid::Uuid,
) -> Result<(), Error> {
    if operation.is_nil() {
        return Err(Error::Malformed);
    }
    lock_device_in(profile, c, tenant, device).await?;
    let changed = sqlx::query(crate::storage_profile::sql(profile).lifecycle_begin_retirement_in_1)
        .bind(tenant)
        .bind(device)
        .bind(operation)
        .execute(c)
        .await
        .map_err(crate::database::db)?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
