//! Runtime pins a durable task-signing authority revision; no private-key file fallback.
use crate::Error;
use serde::Deserialize;
use sqlx::Connection;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub revision: u64,
}
pub(crate) async fn open(
    config: &Config,
    database: &crate::config::Database,
    tenant: rss_request_context::TenantId,
    protection: &rss_mdm_native_protection::Protector,
) -> Result<rss_mdm_execution_service::task_signing::trust::Loaded, Error> {
    let mut c = sqlx::PgConnection::connect_with(&database.options()?)
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    let mut tx = c
        .begin()
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','3000',true)",
    )
    .bind(tenant.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    let loaded = rss_mdm_execution_service::task_signing::trust::load(
        &mut tx,
        tenant,
        config.revision,
        protection,
    )
    .await?;
    tx.rollback()
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    c.close()
        .await
        .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
    Ok(loaded)
}
