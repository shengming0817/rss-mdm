//! Exact union of privileges required by the shared host transaction role.
use rss_mdm_execution_service::{Error, Failure};
use rss_transactional_messaging_postgres::PgTransaction;
fn contract() -> String {
    let mut sql = include_str!("command-admission.sql").to_owned();
    sql = sql.replace(
        "{agent_update_columns}",
        rss_mdm_agent_channel::UPDATE_COLUMNS,
    );
    sql = sql.replace(
        "{agent_allowed_tables}",
        rss_mdm_agent_channel::ALLOWED_TABLES,
    );
    sql = sql.replace(
        "{windows_update_columns}",
        rss_mdm_windows_channel::UPDATE_COLUMNS,
    );
    sql = sql.replace(
        "{windows_allowed_tables}",
        rss_mdm_windows_channel::ALLOWED_TABLES,
    );
    sql = sql.replace(
        "{apple_update_columns}",
        rss_mdm_apple_channel::UPDATE_COLUMNS,
    );
    sql = sql.replace(
        "{apple_allowed_tables}",
        rss_mdm_apple_channel::ALLOWED_TABLES,
    );
    sql
}
pub(super) async fn admit(
    tx: &mut PgTransaction<'_>,
) -> std::result::Result<(), rss_mdm_execution_service::transaction::Fault> {
    tx.with_connection(|c| Box::pin(rss_mdm_execution_service::source_changes::verify_storage(c)))
        .await?;
    tx.with_connection(|c| {
        Box::pin(async move {
            rss_mdm_agent_channel::verify_delivery(c).await?;
            rss_mdm_windows_channel::verify_delivery(c).await?;
            rss_mdm_inventory_postgres::verify_asset_history(c).await?;
            rss_mdm_execution_service::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command authority admission: {e}"))?;
            rss_mdm_authorization_service::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command authorization admission: {e}"))?;
            rss_mdm_registration_service::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command registration admission: {e}"))?;
            rss_mdm_device_service::verify_authority(c)
                .await
                .inspect_err(|e| eprintln!("command device admission: {e}"))?;
            rss_mdm_inventory_postgres::verify_collections(c)
                .await
                .map_err(|_| sqlx::Error::Protocol("collection execution admission".into()))
        })
    })
    .await?;
    let (allowed, rejected_sources) = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_as::<_, (bool, Option<String>)>(sqlx::AssertSqlSafe(contract()))
                    .fetch_one(c)
                    .await
                    .inspect_err(|e| eprintln!("command catalog admission: {e}"))
            })
        })
        .await?;
    if !allowed {
        eprintln!(
            "command admission: runtime authority rejected; tenant isolation sources: {}",
            rejected_sources.as_deref().unwrap_or("valid")
        );
        return Err(Error::Unavailable(Failure::CommandInvariant).into());
    }
    Ok(())
}
