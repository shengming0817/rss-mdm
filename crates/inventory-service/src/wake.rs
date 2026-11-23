use sqlx::PgConnection;
pub(crate) async fn notify(c: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_notify('mdm_work','inventory')")
        .execute(c)
        .await?;
    Ok(())
}
pub(crate) async fn task(
    tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
    payload: &'static str,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query("SELECT pg_notify('mdm_work',$1)")
                .bind(payload)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
