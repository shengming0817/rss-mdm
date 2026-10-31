use super::*;
pub async fn wake_native_in(
    messaging: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    messaging
        .wake_in(
            tx,
            &target(tx.tenant_id(), device),
            &rss_reconcile::ResourceSet::empty(tx.tenant_id()),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    Ok(())
}
