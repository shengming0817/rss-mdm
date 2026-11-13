use super::*;
pub async fn wake_native_in(
    messaging: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<()> {
    messaging
        .wake_in(
            tx,
            &target(tx.tenant_id(), device),
            &crate::lifecycle::resources::device(
                tx.tenant_id(),
                device,
                crate::lifecycle::resources::Work::Exclusive,
            ),
            (),
            |_, _| Box::pin(async { Ok(()) }),
        )
        .await?;
    Ok(())
}
