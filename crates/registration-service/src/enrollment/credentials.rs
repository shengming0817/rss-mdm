//! Bounded, zeroizing credential references for the Windows enrollment handoff only.
use crate::Error;
use rss_mdm_authorization_service::credential::RequestCredential;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;
struct Entry {
    secret: RequestCredential,
    expires: Instant,
}
pub struct Credentials {
    entries: Mutex<HashMap<Uuid, Entry>>,
    clock: Arc<dyn rss_observation::Clock>,
    limit: usize,
}
impl Credentials {
    pub fn new(clock: Arc<dyn rss_observation::Clock>, limit: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            clock,
            limit,
        }
    }
    pub fn insert(&self, secret: RequestCredential) -> Result<Uuid, Error> {
        let now = self.clock.now();
        let mut entries = self.entries.lock().map_err(|_| Error::Runtime)?;
        entries.retain(|_, entry| entry.expires > now);
        if entries.len() >= self.limit {
            return Err(Error::Capacity);
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
    /// Replays never reference the newly supplied credential. Confirmed failures also
    /// leave no committed reference; ambiguous settlement must retain it until expiry.
    pub(crate) fn settle<T>(
        &self,
        reference: Uuid,
        result: Result<T, Error>,
        replayed: bool,
    ) -> Result<T, Error> {
        let unused = match &result {
            Ok(_) => replayed,
            Err(Error::CommitUnknown | Error::RollbackFailed) => false,
            Err(_) => true,
        };
        if unused && let Ok(mut entries) = self.entries.lock() {
            entries.remove(&reference);
        }
        result
    }
    /// A missing or expired process-local continuation requires explicit owner resume.
    pub fn available(&self, reference: Uuid) -> Result<bool, Error> {
        let now = self.clock.now();
        let mut entries = self.entries.lock().map_err(|_| Error::Runtime)?;
        entries.retain(|_, entry| entry.expires > now);
        Ok(entries.contains_key(&reference))
    }
    pub fn get(&self, reference: Uuid) -> Result<RequestCredential, Error> {
        let now = self.clock.now();
        let mut entries = self.entries.lock().map_err(|_| Error::Runtime)?;
        entries.retain(|_, entry| entry.expires > now);
        let entry = entries.get(&reference).ok_or(Error::Unauthorized)?;
        entry.secret.duplicate().map_err(|_| Error::Unauthorized)
    }
}

#[cfg(test)]
#[path = "../../tests/credentials.rs"]
mod tests;
