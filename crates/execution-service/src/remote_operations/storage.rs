use super::*;
pub async fn read_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<Remote> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT frozen,deadline,cancelled,staged,snapshot FROM mdm_planning.remote_operations WHERE tenant_id=$1::uuid AND id=$2 FOR SHARE").bind(tenant).bind(id).fetch_optional(c).await
    })).await?.ok_or(Error::NotFound)?;
    Ok(Remote {
        id,
        frozen: stored(serde_json::from_value(row.try_get("frozen")?))?,
        deadline: row.try_get("deadline")?,
        cancelled: row.try_get("cancelled")?,
        staged: row.try_get("staged")?,
        snapshot: stored(serde_json::from_value(row.try_get("snapshot")?))?,
    })
}
pub async fn allowed_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    device: &str,
    now: i64,
) -> Result<bool> {
    let remote = read_in(tx, id).await?;
    if remote.cancelled || remote.deadline <= now {
        return Ok(false);
    }
    let tenant = tx.tenant_id().to_string();
    let device = device.to_owned();
    Ok(tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.remote_operation_targets WHERE tenant_id=$1::uuid AND operation=$2 AND device=$3 AND status='accepted')").bind(tenant).bind(id).bind(device).fetch_one(c).await
    })).await?)
}
pub async fn wake_in(tx: &mut PgTransaction<'_>, id: Uuid) -> Result<()> {
    let target = rss_reconcile::Target::new(
        crate::recovery_scope(tx.tenant_id()),
        format!("remote:{id}"),
    )
    .map_err(|_| Error::Malformed)?;
    rss_reconcile_postgres::messaging::wake_in(tx, &target, (), |_, _| Box::pin(async { Ok(()) }))
        .await?;
    crate::worker_wake::notify_in(tx, crate::worker_wake::Work::CommandRecovery).await?;
    Ok(())
}
pub fn authorize(
    proof: &AuthorizedPrincipal,
    snapshot: &Snapshot,
    permission: Permission,
) -> std::result::Result<(), Error> {
    match snapshot {
        Snapshot::Devices { devices } => {
            for d in devices {
                proof.require(permission, Some(d))?;
            }
            Ok(())
        }
        Snapshot::Scope { .. } => proof.require_all_devices(permission).map_err(Error::from),
    }
}
