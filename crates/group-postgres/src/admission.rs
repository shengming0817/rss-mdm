//! This owner checks Group schema and effective privileges; RSS checks its own schema.
use crate::storage::{StorageFault, data};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
pub(crate) async fn verify(tx: &mut PgTransaction<'_>) -> Result<(), PgError> {
    let (accepted, catalog) = tx
        .with_connection(|c| {
            Box::pin(async move {
                let accepted = sqlx::query_scalar::<_, bool>(include_str!("admission.sql"))
                    .fetch_one(&mut *c)
                    .await?;
                let catalog = sqlx::query_scalar::<_, String>(include_str!("catalog.sql"))
                    .fetch_one(c)
                    .await?;
                Ok((accepted, catalog))
            })
        })
        .await?;
    let actual: serde_json::Value = data(serde_json::from_str(&catalog))?;
    let expected: serde_json::Value = data(serde_json::from_str(include_str!("catalog.json")))?;
    if accepted && actual == expected {
        Ok(())
    } else {
        Err(StorageFault::Contract.error())
    }
}
