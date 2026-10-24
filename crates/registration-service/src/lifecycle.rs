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
    // Close the complete parent/child set under its endpoint fence before invoking participants.
    let device: String = sqlx::query_scalar(
        "SELECT device FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(registration)
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::database::db)?;
    lock_device_in(tx, tenant, &device).await?;
    sqlx::query(
        "SELECT id FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(registration)
    .execute(&mut *tx)
    .await
    .map_err(crate::database::db)?;
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
    lock_devices_in(c, tenant, &[device.to_owned()]).await
}
/// Acquire a page's endpoint fences in the same lexical order as single-device writers.
pub async fn lock_devices_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<(), Error> {
    if devices.len() > 1000 {
        return Err(Error::Malformed);
    }
    sqlx::query("SELECT mdm.lock_asset_watermark($1::uuid)")
        .bind(tenant)
        .execute(&mut *c)
        .await
        .map_err(crate::database::db)?;
    let keys = devices
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|device| serde_json::to_string(&(tenant, device)).map_err(|_| Error::Malformed))
        .collect::<Result<Vec<_>, _>>()?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(key,2790)) FROM unnest($1::text[]) WITH ORDINALITY locks(key,n) ORDER BY n").bind(keys).execute(c).await.map_err(crate::database::db)?;
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

/// A new administrator enrollment may reopen a fully retired endpoint. Old
/// enrollment authority is cancelled before clearing the fence in this transaction.
pub(crate) async fn authorize_reenrollment_in(
    c: &mut sqlx::PgConnection,
    proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
    device: &str,
) -> Result<(), Error> {
    use rss_mdm_authorization_service as auth;
    proof.enrollment(device)?.check()?;
    auth::lock_on(c, proof.tenant_id(), proof.instance_id()).await?;
    auth::snapshot_on(c, proof.tenant_id(), proof.instance_id())
        .await?
        .require(proof, auth::Permission::Enrollment, Some(device))
        .map_err(|_| Error::Forbidden)?;
    lock_device_in(c, proof.tenant_id(), device).await?;
    let retirement: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT retirement FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(proof.tenant_id())
    .bind(device)
    .fetch_optional(&mut *c)
    .await
    .map_err(crate::database::db)?
    .flatten();
    let Some(retirement) = retirement else {
        return Ok(());
    };
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mdm_access.devices d JOIN mdm_access.registrations r ON(r.tenant_id,r.device)=(d.tenant_id,d.id) WHERE d.tenant_id=$1::uuid AND d.retirement=$2 AND r.state='active')",
    ).bind(proof.tenant_id()).bind(retirement).fetch_one(&mut *c).await.map_err(crate::database::db)?;
    if active {
        return Err(Error::Conflict);
    }
    sqlx::query("UPDATE mdm_access.requests r SET state='cancelled' FROM mdm_access.grants g WHERE(r.tenant_id,r.grant_id)=(g.tenant_id,g.id) AND g.tenant_id=$1::uuid AND g.device=$2 AND r.state='pending'")
        .bind(proof.tenant_id()).bind(device).execute(&mut *c).await.map_err(crate::database::db)?;
    sqlx::query("UPDATE mdm_access.agent_grants SET state='revoked' WHERE tenant_id=$1::uuid AND device=$2 AND state<>'revoked'")
        .bind(proof.tenant_id()).bind(device).execute(&mut *c).await.map_err(crate::database::db)?;
    sqlx::query("UPDATE mdm_access.devices SET retirement=NULL WHERE tenant_id=$1::uuid AND id=$2")
        .bind(proof.tenant_id())
        .bind(device)
        .execute(c)
        .await
        .map_err(crate::database::db)?;
    proof.check_live()?;
    Ok(())
}
