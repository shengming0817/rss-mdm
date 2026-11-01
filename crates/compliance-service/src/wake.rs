pub(crate) async fn task(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    payload: &'static str,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT pg_notify('mdm_work_' || replace(current_setting('rss.tenant_id')::uuid::text,'-',''),$1)").bind(payload).execute(c).await?;
        Ok(())
    })).await
}
