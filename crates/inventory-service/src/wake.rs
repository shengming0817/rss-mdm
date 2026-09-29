use sqlx::PgConnection;
pub(crate) async fn notify(c: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'inventory')").execute(c).await?;
    Ok(())
}
pub(crate) async fn wait(
    notify: &tokio::sync::Notify,
    stop: &tokio_util::sync::CancellationToken,
    nearest: Option<std::time::Duration>,
) {
    let recovery = std::time::Duration::from_secs(5);
    tokio::select! {biased;()=stop.cancelled()=>{},()=notify.notified()=>{},()=tokio::time::sleep(nearest.unwrap_or(recovery).min(recovery))=>{}}
}

pub(crate) async fn automation(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    tx.with_connection(|c|Box::pin(async move{sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),'automation')").execute(c).await?;Ok(())})).await
}
