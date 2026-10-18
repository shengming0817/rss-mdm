use crate::Error;
use std::{future::Future, pin::Pin};
/// Participate after registration state is retired, using the same borrowed transaction.
pub trait Retirement: Send + Sync {
    fn retire<'a>(
        &'a self,
        tx: &'a mut sqlx::PgConnection,
        facts: &'a mut Vec<rss_mdm_audit_integration::Fact>,
        tenant: &'a str,
        registration: uuid::Uuid,
        state: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}
pub async fn retire(
    tx: &mut sqlx::PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
    registration: uuid::Uuid,
    state: &str,
    participant: &dyn Retirement,
) -> Result<(), Error> {
    // The caller owns the device/channel lock; parent before children is the common order.
    let children = sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND parent_id=$2 AND state='active' ORDER BY id FOR UPDATE")
        .bind(tenant).bind(registration).fetch_all(&mut *tx).await.map_err(crate::database::db)?;
    crate::device::store::retire_state_in(tx, tenant, registration, state).await?;
    for child in children {
        crate::device::store::retire_state_in(tx, tenant, child, state).await?;
        participant.retire(tx, facts, tenant, child, state).await?;
    }
    participant
        .retire(tx, facts, tenant, registration, state)
        .await
}

/// Fence all channels of one endpoint, including enrollment which has no row yet.
/// Callers acquiring more than one endpoint lock must use lexical device order.
pub async fn lock_device_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<(), Error> {
    let key = serde_json::to_string(&(tenant, device)).map_err(|_| Error::Malformed)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2790))")
        .bind(key)
        .execute(c)
        .await
        .map_err(crate::database::db)?;
    Ok(())
}

/// Normal work and enrollment cannot cross an accepted retirement. Authentication
/// remains separate so the exact cleanup operation can still receive its evidence.
pub async fn require_work_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<(), Error> {
    if !work_allowed_in(c, tenant, device).await? {
        return Err(Error::Forbidden);
    }
    Ok(())
}

pub async fn work_allowed_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
) -> Result<bool, Error> {
    lock_device_in(c, tenant, device).await?;
    let exit: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT retirement FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
    )
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
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &str,
    operation: uuid::Uuid,
) -> Result<(), Error> {
    if operation.is_nil() {
        return Err(Error::Malformed);
    }
    lock_device_in(c, tenant, device).await?;
    let changed = sqlx::query("UPDATE mdm_access.devices SET retirement=$3 WHERE tenant_id=$1::uuid AND id=$2 AND (retirement IS NULL OR retirement=$3)")
        .bind(tenant).bind(device).bind(operation).execute(c).await.map_err(crate::database::db)?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
