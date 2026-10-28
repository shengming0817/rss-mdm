//! This owner checks Group schema and effective privileges; RSS checks its own schema.
use crate::storage::StorageFault;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
pub(crate) async fn verify(tx: &mut PgTransaction<'_>) -> Result<(), PgError> {
    let accepted = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    let body = crate::MIGRATION_SQL
        .split_once("CREATE FUNCTION mdm_group.group_current(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let rejected = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, String>(include_str!("authority-admission.sql"))
                    .bind(body)
                    .fetch_optional(c)
                    .await
            })
        })
        .await?;
    if accepted && rejected.is_none() {
        Ok(())
    } else {
        Err(StorageFault::Contract.error())
    }
}
