use crate::Error;
use std::{future::Future, pin::Pin};
pub mod resources;

/// PostgreSQL key used by endpoint writers, recovery readers and product SQL triggers.
/// The arguments are trusted SQL expressions for the tenant and device UUIDs.
#[macro_export]
macro_rules! endpoint_lock_key_sql {
    ($tenant:literal,$device:literal) => {
        concat!(
            r#"hashtextextended(format('["%s","%s"]',"#,
            $tenant,
            ",",
            $device,
            "),2790)"
        )
    };
}

/// A run recovery may share the lifecycle fence only when it neither admits new
/// device work nor mutates registration/channel state. Retirement and foreground
/// writers retain the exclusive fence. Resource admission still serializes runs
/// of the same kind before their protected effect.
pub async fn lock_recovery_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<(), Error> {
    sqlx::query(concat!(
        "SELECT pg_advisory_xact_lock_shared(",
        crate::endpoint_lock_key_sql!("$1::text", "$2::uuid"),
        ")"
    ))
    .bind(tenant)
    .bind(device.into_uuid())
    .execute(c)
    .await
    .map_err(crate::database::db)?;
    Ok(())
}

/// Nonblocking counterpart for Script and Agent Collection run recovery.
pub async fn try_lock_recovery_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<bool, Error> {
    sqlx::query_scalar(concat!(
        "SELECT pg_try_advisory_xact_lock_shared(",
        crate::endpoint_lock_key_sql!("$1::text", "$2::uuid"),
        ")"
    ))
    .bind(tenant)
    .bind(device.into_uuid())
    .fetch_one(c)
    .await
    .map_err(crate::database::db)
}
/// Participate after registration state is retired, using the same borrowed transaction.
pub trait Retirement: Send + Sync {
    /// The host's optional event destination, fixed with this lifecycle participant.
    fn events(&self) -> Option<&dyn crate::EventSink>;
    fn retire<'a>(
        &'a self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        tx: &'a mut sqlx::PgConnection,
        facts: &'a mut Vec<rss_mdm_audit_integration::Fact>,
        tenant: &'a str,
        device: &'a rss_mdm_agent_wire::DeviceId,
        state: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}
#[allow(
    clippy::too_many_arguments,
    reason = "keep execution scope and existing operation inputs explicit"
)]
pub async fn retire(
    execution: rss_transactional_messaging::fence::ExecutionBinding,
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    state: &str,
    participant: &dyn Retirement,
) -> Result<(), Error> {
    lock_device_in(profile, tx, tenant, device).await?;
    // Credentials and protocol requests close with their device in this transaction.
    crate::device::store::retire_state_in(profile, tx, tenant, device, state, participant.events())
        .await?;
    participant
        .retire(execution, tx, facts, tenant, device, state)
        .await
}

/// The product's single endpoint fence: registration, execution and all channels,
/// including enrollment which has no row yet. Held until transaction settlement.
/// ref: PostgreSQL src/backend/utils/adt/lockfuncs.c (transaction advisory locks).
/// Callers acquiring more than one endpoint lock must use lexical device order.
pub async fn lock_device_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<(), Error> {
    lock_devices_in(profile, c, tenant, &[device.to_owned()]).await
}
/// Acquire a page's endpoint fences in the same lexical order as single-device writers.
pub async fn lock_devices_in(
    _profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[rss_mdm_agent_wire::DeviceId],
) -> Result<(), Error> {
    let ids = ordered_devices(devices)?;
    sqlx::query(concat!(
        "SELECT pg_advisory_xact_lock(",
        crate::endpoint_lock_key_sql!("$1::text", "device"),
        ") FROM unnest($2::uuid[]) WITH ORDINALITY locks(device,n) ORDER BY n"
    ))
    .bind(tenant)
    .bind(ids)
    .execute(c)
    .await
    .map_err(crate::database::db)?;
    Ok(())
}

/// Try an endpoint page without waiting behind device writers while a caller holds directory locks.
/// Roll back partial multi-endpoint acquisition before returning false. The caller
/// still owns transaction settlement; successful fences live until that settlement.
pub async fn try_lock_devices_in(
    _profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[rss_mdm_agent_wire::DeviceId],
) -> Result<bool, Error> {
    let ids = ordered_devices(devices)?;
    let batch = ids.len() > 1;
    if batch {
        sqlx::query("SAVEPOINT mdm_endpoint_fences")
            .execute(&mut *c)
            .await
            .map_err(crate::database::db)?;
    }
    for id in ids {
        let locked: bool = sqlx::query_scalar(concat!(
            "SELECT pg_try_advisory_xact_lock(",
            crate::endpoint_lock_key_sql!("$1::text", "$2::uuid"),
            ")"
        ))
        .bind(tenant)
        .bind(id)
        .fetch_one(&mut *c)
        .await
        .map_err(crate::database::db)?;
        if !locked {
            if batch {
                sqlx::query("ROLLBACK TO SAVEPOINT mdm_endpoint_fences")
                    .execute(&mut *c)
                    .await
                    .map_err(crate::database::db)?;
                sqlx::query("RELEASE SAVEPOINT mdm_endpoint_fences")
                    .execute(&mut *c)
                    .await
                    .map_err(crate::database::db)?;
            }
            return Ok(false);
        }
    }
    if batch {
        sqlx::query("RELEASE SAVEPOINT mdm_endpoint_fences")
            .execute(c)
            .await
            .map_err(crate::database::db)?;
    }
    Ok(true)
}
fn ordered_devices(devices: &[rss_mdm_agent_wire::DeviceId]) -> Result<Vec<uuid::Uuid>, Error> {
    if devices.len() > 1024 {
        return Err(Error::Malformed);
    }
    let mut ids = devices
        .iter()
        .map(|device| device.into_uuid())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// Normal work and enrollment cannot cross an accepted retirement. Authentication
/// remains separate so the exact cleanup operation can still receive its evidence.
pub async fn require_work_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
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
    device: &rss_mdm_agent_wire::DeviceId,
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
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<bool, Error> {
    let exit: Option<uuid::Uuid> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).lifecycle_work_allowed_on_1)
            .bind(tenant)
            .bind(device.into_uuid())
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
    device: &rss_mdm_agent_wire::DeviceId,
    operation: uuid::Uuid,
) -> Result<(), Error> {
    if operation.is_nil() {
        return Err(Error::Malformed);
    }
    lock_device_in(profile, c, tenant, device).await?;
    let changed = sqlx::query(crate::storage_profile::sql(profile).lifecycle_begin_retirement_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(operation)
        .execute(c)
        .await
        .map_err(crate::database::db)?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
