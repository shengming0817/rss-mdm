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
#[path = "../../tests/enrollment/credentials_unit.rs"]
mod tests;

/// Enrollment-only continuation of the current authenticated browser session.
#[derive(Clone)]
pub(crate) struct SessionContinuation(Arc<SessionSecret>);
impl SessionContinuation {
    pub(crate) fn new(secret: SessionSecret) -> Self {
        Self(Arc::new(secret))
    }
    pub(super) fn retain(&self, credentials: &Credentials) -> Result<Uuid, Error> {
        credentials
            .insert(SessionSecret::parse(self.0.expose().into()).map_err(|_| Error::Unauthorized)?)
    }
}
