//! Bounded process-local credential storage; no cached verified identity.
use crate::Error;
use crate::Failure;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{Nonce, PkceCodeVerifier};
use rand::RngCore;
use rss_identity_client::Clock;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) fn random() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(crate) fn equal(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
pub(crate) fn valid(value: &str) -> bool {
    value.len() == 43 && URL_SAFE_NO_PAD.decode(value).is_ok_and(|v| v.len() == 32)
}
pub(crate) struct Pending {
    pub browser: String,
    pub old_session: Option<String>,
    pub nonce: Nonce,
    pub verifier: PkceCodeVerifier,
    pub expires: i64,
}
pub(crate) struct Session {
    pub credential: Zeroizing<String>,
    pub subject: String,
    pub identity_session: String,
    pub csrf: String,
    pub expires: i64,
}
pub(crate) struct Lease {
    pub requests: Arc<tokio::sync::Semaphore>,
    pub id: String,
    pub credential: Zeroizing<String>,
    pub subject: String,
    pub identity_session: String,
    pub csrf: String,
}
struct Inner {
    pending: HashMap<String, Pending>,
    sessions: HashMap<String, (Session, Arc<tokio::sync::Semaphore>)>,
    references: HashMap<uuid::Uuid, (String, i64)>,
    last_time: i64,
}
pub(crate) struct Sessions {
    inner: Mutex<Inner>,
    clock: Arc<dyn Clock>,
    pending_limit: usize,
    session_limit: usize,
}
impl Sessions {
    pub fn new(clock: Arc<dyn Clock>, pending_limit: usize, session_limit: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                pending: HashMap::new(),
                sessions: HashMap::new(),
                references: HashMap::new(),
                last_time: 0,
            }),
            clock,
            pending_limit,
            session_limit,
        }
    }
    fn lock(&self) -> Result<(std::sync::MutexGuard<'_, Inner>, i64), Error> {
        let now = self
            .clock
            .unix_seconds()
            .map_err(|_| Error::Unavailable(Failure::Clock))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| Error::Unavailable(Failure::SessionState))?;
        if now <= 0 || now < state.last_time {
            return Err(Error::Unavailable(Failure::Clock));
        }
        if now > state.last_time {
            state.pending.retain(|_, p| p.expires > now);
            state.sessions.retain(|_, (s, _)| s.expires > now);
            state.references.retain(|_, (_, expires)| *expires > now);
            state.last_time = now;
        }
        Ok((state, now))
    }
    pub fn now(&self) -> Result<i64, Error> {
        Ok(self.lock()?.1)
    }
    pub fn begin(&self, state: String, pending: Pending) -> Result<(), Error> {
        let (mut inner, now) = self.lock()?;
        if inner
            .pending
            .values()
            .filter(|p| p.browser == pending.browser)
            .count()
            >= 4
        {
            return Err(Error::Unavailable(Failure::Capacity));
        }
        if inner.pending.len() >= self.pending_limit || inner.pending.contains_key(&state) {
            return Err(Error::Unavailable(Failure::Capacity));
        }
        if pending.expires <= now || pending.expires > now + 300 {
            return Err(Error::Malformed);
        }
        inner.pending.insert(state, pending);
        Ok(())
    }
    pub fn consume(&self, state: &str, browser: &str, old: Option<&str>) -> Result<Pending, Error> {
        let (mut inner, _) = self.lock()?;
        let p = inner.pending.get(state).ok_or(Error::Unauthorized)?;
        if !equal(&p.browser, browser) || p.old_session.as_deref() != old {
            return Err(Error::Unauthorized);
        }
        inner.pending.remove(state).ok_or(Error::Unauthorized)
    }
    pub fn establish(&self, old: Option<&str>, session: Session) -> Result<String, Error> {
        let (mut inner, now) = self.lock()?;
        if session.expires <= now {
            return Err(Error::Unauthorized);
        }
        if let Some(id) = old
            && !inner.sessions.contains_key(id)
        {
            return Err(Error::Unauthorized);
        }
        if old.is_none() && inner.sessions.len() >= self.session_limit {
            return Err(Error::Unavailable(Failure::Capacity));
        }
        let id = random();
        if let Some(old) = old {
            inner.sessions.remove(old);
        }
        inner.sessions.insert(
            id.clone(),
            (session, Arc::new(tokio::sync::Semaphore::new(1))),
        );
        Ok(id)
    }
    pub fn get(&self, id: &str) -> Result<Lease, Error> {
        let (inner, _) = self.lock()?;
        let (s, requests) = inner.sessions.get(id).ok_or(Error::Unauthorized)?;
        Ok(Lease {
            requests: requests.clone(),
            id: id.into(),
            credential: Zeroizing::new(s.credential.to_string()),
            subject: s.subject.clone(),
            identity_session: s.identity_session.clone(),
            csrf: s.csrf.clone(),
        })
    }
    /// Non-login references resolve only through the enrollment password + online Identity path.
    pub fn reference(&self, lease: &Lease) -> Result<uuid::Uuid, Error> {
        let (mut inner, now) = self.lock()?;
        if !inner.sessions.contains_key(&lease.id) {
            return Err(Error::Unauthorized);
        }
        if inner.references.len() >= self.session_limit {
            return Err(Error::Unavailable(Failure::Capacity));
        }
        let id = uuid::Uuid::new_v4();
        inner.references.insert(id, (lease.id.clone(), now + 300));
        Ok(id)
    }
    pub fn by_reference(&self, reference: uuid::Uuid) -> Result<Lease, Error> {
        let id = {
            let (inner, _) = self.lock()?;
            inner
                .references
                .get(&reference)
                .ok_or(Error::Unauthorized)?
                .0
                .clone()
        };
        self.get(&id)
    }
    pub fn remove(&self, id: &str, csrf: &str) -> Result<(), Error> {
        // Cleanup never depends on remote Identity or the wall clock being available.
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Error::Unavailable(Failure::SessionState))?;
        let (s, _) = inner.sessions.get(id).ok_or(Error::Unauthorized)?;
        if !equal(&s.csrf, csrf) {
            return Err(Error::Forbidden);
        }
        inner.sessions.remove(id);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    struct Time(AtomicI64);
    impl Clock for Time {
        fn unix_seconds(&self) -> Result<i64, rss_identity_client::Error> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }
    fn pending() -> Pending {
        Pending {
            browser: "browser".into(),
            old_session: None,
            nonce: Nonce::new("nonce".into()),
            verifier: PkceCodeVerifier::new("verifier".into()),
            expires: 1100,
        }
    }
    fn session() -> Session {
        Session {
            credential: Zeroizing::new("credential".into()),
            subject: "subject".into(),
            identity_session: "sid".into(),
            csrf: "csrf".into(),
            expires: 1100,
        }
    }
    #[test]
    fn bounded_single_use_browser_and_expiry() {
        let clock = Arc::new(Time(AtomicI64::new(1000)));
        let store = Sessions::new(clock.clone(), 1, 1);
        store.begin("first".into(), pending()).unwrap();
        assert!(store.begin("second".into(), pending()).is_err());
        assert!(store.consume("first", "wrong", None).is_err());
        store.consume("first", "browser", None).unwrap();
        assert!(store.consume("first", "browser", None).is_err());
        let id = store.establish(None, session()).unwrap();
        assert!(store.establish(None, session()).is_err());
        let replacement = store.establish(Some(&id), session()).unwrap();
        assert!(store.get(&id).is_err());
        assert!(store.remove(&replacement, "wrong").is_err());
        assert!(store.get(&replacement).is_ok());
        clock.0.store(1100, Ordering::SeqCst);
        assert!(store.get(&replacement).is_err());
    }
    #[test]
    fn rollback_rejects_authentication_but_allows_local_logout() {
        let clock = Arc::new(Time(AtomicI64::new(1000)));
        let store = Sessions::new(clock.clone(), 1, 1);
        let id = store.establish(None, session()).unwrap();
        clock.0.store(999, Ordering::SeqCst);
        assert!(store.get(&id).is_err());
        store.remove(&id, "csrf").unwrap();
    }
    #[test]
    fn one_browser_cannot_exhaust_global_pending_and_recovers_after_expiry() {
        let clock = Arc::new(Time(AtomicI64::new(1000)));
        let store = Sessions::new(clock.clone(), 1000, 10);
        for i in 0..4 {
            store.begin(format!("state-{i}"), pending()).unwrap();
        }
        assert!(store.begin("fifth".into(), pending()).is_err());
        let mut different = pending();
        different.browser = "another".into();
        store.begin("another".into(), different).unwrap();
        clock.0.store(1100, Ordering::SeqCst);
        let mut renewed = pending();
        renewed.expires = 1200;
        store.begin("renewed".into(), renewed).unwrap();
    }
}
