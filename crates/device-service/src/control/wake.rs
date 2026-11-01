use crate::control::{Error, transaction::*};
use rss_transactional_messaging_postgres::PgTransaction;

pub async fn wake_native_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    device: &str,
) -> Result<()> {
    wake_native_batch_in(reconcile, tx, &[device.to_owned()]).await
}

/// Coalesced source changes update only interested devices. All wakes and the
/// caller's input checkpoint use this transaction; RSS remains the wake owner.
pub async fn wake_native_batch_in(
    reconcile: &rss_reconcile_postgres::PgMessagingStore,
    tx: &mut PgTransaction<'_>,
    devices: &[String],
) -> Result<()> {
    if devices.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    for device in devices {
        crate::control::unmanage::wake_device_in(reconcile, tx, device).await?;
    }
    Ok(())
}
