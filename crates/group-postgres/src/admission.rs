//! This owner checks Group schema and effective privileges; RSS checks its own schema.
use crate::storage::invariant;
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
    if accepted { Ok(()) } else { Err(invariant()) }
}
