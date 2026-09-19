//! Bounded, zeroizing credential references for the Windows enrollment handoff only.
use crate::{Error, Failure};
use rss_identity_core::session::SessionSecret;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;
struct Entry {
    secret: SessionSecret,
    expires: Instant,
}
pub(crate) struct Credentials {
    entries: Mutex<HashMap<Uuid, Entry>>,
    clock: Arc<dyn rss_observation::Clock>,
    limit: usize,
}
impl Credentials {
    pub(crate) fn new(clock: Arc<dyn rss_observation::Clock>, limit: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            clock,
            limit,
        }
    }
    pub(crate) fn insert(&self, secret: SessionSecret) -> Result<Uuid, Error> {
        let now = self.clock.now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Error::Unavailable(Failure::Runtime))?;
        entries.retain(|_, entry| entry.expires > now);
        if entries.len() >= self.limit {
            return Err(Error::Unavailable(Failure::Capacity));
        }
        let id = Uuid::new_v4();
        entries.insert(
            id,
            Entry {
                secret,
                expires: now + Duration::from_secs(300),
            },
        );
        Ok(id)
    }
    pub(crate) fn get(&self, reference: Uuid) -> Result<SessionSecret, Error> {
        let now = self.clock.now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Error::Unavailable(Failure::Runtime))?;
        entries.retain(|_, entry| entry.expires > now);
        let entry = entries.get(&reference).ok_or(Error::Unauthorized)?;
        SessionSecret::parse(entry.secret.expose().into()).map_err(|_| Error::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Clock(Instant, AtomicU64);
    impl rss_observation::Clock for Clock {
        fn now(&self) -> Instant {
            self.0 + Duration::from_secs(self.1.load(Ordering::SeqCst))
        }
    }
    #[test]
    fn handoff_has_finite_capacity_and_reads_never_renew_it() {
        let clock = Arc::new(Clock(
            rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer),
            AtomicU64::new(0),
        ));
        let cache = Credentials::new(clock.clone(), 1);
        let secret = || SessionSecret::parse("a".repeat(64)).unwrap();
        let id = cache.insert(secret()).unwrap();
        assert!(matches!(
            cache.insert(secret()),
            Err(Error::Unavailable(Failure::Capacity))
        ));
        clock.1.store(299, Ordering::SeqCst);
        assert_eq!(cache.get(id).unwrap().expose(), secret().expose());
        clock.1.store(300, Ordering::SeqCst);
        assert!(matches!(cache.get(id), Err(Error::Unauthorized)));
        assert!(cache.insert(secret()).is_ok());
    }
}
