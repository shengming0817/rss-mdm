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
    let rejected = verify_functions(tx).await?;
    if accepted && rejected.is_none() {
        Ok(())
    } else {
        Err(StorageFault::Contract.error())
    }
}

async fn verify_functions(tx: &mut PgTransaction<'_>) -> Result<Option<String>, PgError> {
    let body = crate::MIGRATION_SQL
        .split_once("CREATE FUNCTION mdm_group.group_current(")
        .expect("owner function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner body");
    let lock_body = crate::MIGRATION_SQL
        .split_once("CREATE FUNCTION mdm_group.lock_reference_target(")
        .expect("owner lock function")
        .1
        .split("$$")
        .nth(1)
        .expect("owner lock body");
    let rejected = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, String>(include_str!("authority-admission.sql"))
                    .bind(body)
                    .bind(lock_body)
                    .fetch_optional(c)
                    .await
            })
        })
        .await?;
    Ok(rejected)
}

pub(crate) async fn verify_sources(tx: &mut PgTransaction<'_>) -> Result<(), PgError> {
    let accepted = tx
        .with_connection(|c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, bool>(include_str!("source-admission.sql"))
                    .fetch_one(c)
                    .await
            })
        })
        .await?;
    if accepted && verify_functions(tx).await?.is_none() {
        Ok(())
    } else {
        Err(StorageFault::Contract.error())
    }
}
