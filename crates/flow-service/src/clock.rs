//! Product wall time for device protocols and operational timestamps; authentication uses PG time.
use crate::{Error, Failure};
pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Result<i64, Error>;
}
pub struct SystemClock;
impl Clock for SystemClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "product wall-clock provider selected at assembly"
    )]
    fn unix_seconds(&self) -> Result<i64, Error> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .ok_or(Error::Unavailable(Failure::Clock))
    }
}

pub struct InventoryClock(pub std::sync::Arc<dyn Clock>);
impl rss_mdm_inventory_service::clock::Clock for InventoryClock {
    fn unix_seconds(&self) -> Option<i64> {
        self.0.unix_seconds().ok()
    }
}

impl rss_mdm_inventory_service::clock::Clock for SystemClock {
    fn unix_seconds(&self) -> Option<i64> {
        Clock::unix_seconds(self).ok()
    }
}
