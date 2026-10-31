use crate::{Error, transaction::*};
use rss_transactional_messaging_postgres::PgTransaction;

pub async fn wake_native_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    source: std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    wake_native_batch_in(reconcile, source, tx, &[device.to_owned()]).await
}

/// Coalesced source changes update only interested devices. All wakes and the
/// caller's input checkpoint use this transaction; RSS remains the wake owner.
pub async fn wake_native_batch_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    _source: std::sync::Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    tx: &mut PgTransaction<'_>,
    devices: &[String],
) -> Result<()> {
    if devices.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    for device in devices {
        crate::unmanage::wake_device_in(reconcile, tx, device).await?;
    }
    Ok(())
}
