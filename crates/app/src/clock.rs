//! Product wall time for device protocols and operational timestamps; authentication uses PG time.
use crate::{Error, Failure};
pub(crate) trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Result<i64, Error>;
}
pub(crate) struct SystemClock;
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

pub(crate) struct InventoryClock(pub(crate) std::sync::Arc<dyn Clock>);
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

pub(crate) struct FlowClock(pub(crate) std::sync::Arc<dyn Clock>);
impl rss_mdm_flow_service::clock::Clock for FlowClock {
    fn unix_seconds(&self) -> Result<i64, rss_mdm_flow_service::Error> {
        self.0.unix_seconds().map_err(|_| {
            rss_mdm_flow_service::Error::Unavailable(rss_mdm_flow_service::Failure::Clock)
        })
    }
}

impl rss_mdm_flow_service::clock::Clock for SystemClock {
    fn unix_seconds(&self) -> Result<i64, rss_mdm_flow_service::Error> {
        Clock::unix_seconds(self).map_err(|_| {
            rss_mdm_flow_service::Error::Unavailable(rss_mdm_flow_service::Failure::Clock)
        })
    }
}

pub(crate) struct ContentClock(pub std::sync::Arc<dyn Clock>);
impl rss_mdm_content_service::service::Clock for ContentClock {
    fn unix_seconds(&self) -> Option<i64> {
        self.0.unix_seconds().ok()
    }
}

impl rss_mdm_software_service::management::Clock for FlowClock {
    fn unix_seconds(&self) -> Option<i64> {
        self.0.unix_seconds().ok()
    }
}
impl rss_mdm_software_service::management::Clock for ContentClock {
    fn unix_seconds(&self) -> Option<i64> {
        self.0.unix_seconds().ok()
    }
}
