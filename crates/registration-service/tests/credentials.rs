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
        rss_request_context::Clock::now(&rss_mdm_audit_integration::budget::RuntimeTimer),
        AtomicU64::new(0),
    ));
    let cache = Credentials::new(clock.clone(), 1);
    let secret = || SessionSecret::parse("a".repeat(64)).unwrap();
    let id = cache.insert(secret()).unwrap();
    assert!(matches!(cache.insert(secret()), Err(Error::Capacity)));
    clock.1.store(299, Ordering::SeqCst);
    assert_eq!(cache.get(id).unwrap().expose(), secret().expose());
    clock.1.store(300, Ordering::SeqCst);
    assert!(matches!(cache.get(id), Err(Error::Unauthorized)));
    assert!(cache.insert(secret()).is_ok());
}

#[test]
fn settled_unused_handoffs_release_capacity_but_unknown_commits_retain_it() {
    let clock = Arc::new(Clock(
        rss_request_context::Clock::now(&rss_mdm_audit_integration::budget::RuntimeTimer),
        AtomicU64::new(0),
    ));
    let cache = Credentials::new(clock, 1);
    let secret = || SessionSecret::parse("a".repeat(64)).unwrap();
    for _ in 0..5 {
        let id = cache.insert(secret()).unwrap();
        assert!(matches!(
            cache.settle::<()>(id, Err(Error::RegistrationLimit), false),
            Err(Error::RegistrationLimit)
        ));
    }
    let id = cache.insert(secret()).unwrap();
    cache.settle(id, Ok(()), true).unwrap();
    assert!(matches!(cache.get(id), Err(Error::Unauthorized)));
    let id = cache.insert(secret()).unwrap();
    assert!(
        cache
            .settle::<()>(id, Err(Error::CommitUnknown), false)
            .is_err()
    );
    assert!(cache.get(id).is_ok());
    assert!(matches!(cache.insert(secret()), Err(Error::Capacity)));
}
