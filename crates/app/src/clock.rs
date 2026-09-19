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
