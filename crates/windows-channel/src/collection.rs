//! Session termination for policy-owned template and channel maintenance runs.
use crate::{Error, Failure, database::db};
use rss_mdm_inventory_service::collection::store;
use uuid::Uuid;
fn corrupt() -> Error {
    Error::Unavailable(Failure::Database)
}
pub async fn terminate_session(
    tx: &mut sqlx::PgConnection,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    tenant: &str,
    registration: &str,
    session: &str,
    reason: &str,
) -> Result<(), Error> {
    let ids: Vec<String> = sqlx::query_scalar("SELECT id::text FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND registration=$2::uuid AND session_id=$3 ORDER BY first_command,id")
        .bind(tenant).bind(registration).bind(session).fetch_all(&mut *tx).await.map_err(db)?;
    for id in ids {
        let native:bool=sqlx::query_scalar("SELECT kind='agent' FROM mdm_windows.collections WHERE tenant_id=$1::uuid AND id=$2::uuid AND session_id=$3").bind(tenant).bind(&id).bind(session).fetch_one(&mut *tx).await.map_err(db)?;
        if native || reason == "aborted" {
            facts.extend(
                rss_mdm_inventory_service::collection::channel::abandon_in(
                    tx,
                    tenant,
                    Uuid::parse_str(&id).map_err(|_| corrupt())?,
                    reason,
                )
                .await?,
            );
            continue;
        }
        let mut run =
            store::load_on(tx, tenant, Uuid::parse_str(&id).map_err(|_| corrupt())?).await?;
        if run.sealed_at.is_none() {
            facts.extend(store::seal(tx, &mut run, reason).await?);
        }
    }
    Ok(())
}
