use rss_mdm_recovery_observation::{ObservedStore, Phase, Readiness};
use rss_reconcile::*;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

struct Clock;
impl Timer for Clock {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
    async fn sleep_until(&self, _: Duration) {
        std::future::pending().await
    }
}
struct Token(Target);
impl Claim for Token {
    fn target(&self) -> &Target {
        &self.0
    }
    fn failures(&self) -> u32 {
        1
    }
}
#[derive(Default)]
struct Provider {
    scan_fails: AtomicBool,
    finish_fails: AtomicBool,
}
impl DurableStore for Provider {
    type Claim = Token;
    async fn wake<T: Timer>(
        &self,
        _: &Target,
        _: &ResourceSet,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn bind_resources<T: Timer>(
        &self,
        _: &Target,
        _: &ResourceSet,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn claim_due<T: Timer>(
        &self,
        _: &Scope,
        _: usize,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<ClaimBatch<Token>, Error> {
        if self.scan_fails.load(Ordering::Relaxed) {
            Err(Error::new(ErrorKind::Transient))
        } else {
            Ok(ClaimBatch {
                claims: Vec::new(),
                more: false,
            })
        }
    }
    async fn renew<T: Timer>(
        &self,
        _: &Token,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn release<T: Timer>(&self, _: &Token, _: &Control<'_, T>) -> Result<(), Error> {
        Ok(())
    }
    async fn finish<T: Timer>(
        &self,
        _: &Token,
        _: Completion,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        if self.finish_fails.load(Ordering::Relaxed) {
            Err(Error::new(ErrorKind::CommitUnknown))
        } else {
            Ok(())
        }
    }
}
fn scope(name: &str) -> Scope {
    Scope::new(
        rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
        name,
    )
    .unwrap()
}
fn fail(readiness: &Readiness, target: &Target) {
    readiness.observe(&Observation::AttemptFailed {
        target: target.clone(),
        stage: Stage::Apply,
        error: Error::new(ErrorKind::Permanent),
    });
}

#[tokio::test]
async fn only_same_scope_scan_and_confirmed_target_finish_recover_health() {
    let scope = scope("software");
    let health = Readiness::new(scope.clone(), true, false);
    let provider = Provider::default();
    let store = ObservedStore::new(&provider, &health);
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&Clock, Duration::from_secs(1), &cancel);
    provider.scan_fails.store(true, Ordering::Relaxed);
    assert!(
        store
            .claim_due(&scope, 1, Duration::from_secs(1), &control)
            .await
            .is_err()
    );
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Transient)
    );
    provider.scan_fails.store(false, Ordering::Relaxed);
    let unrelated = Scope::new(scope.tenant(), "collection").unwrap();
    assert!(
        store
            .claim_due(&unrelated, 1, Duration::from_secs(1), &control)
            .await
            .is_err()
    );
    health.relay(Ok(()));
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Transient)
    );
    assert!(
        store
            .claim_due(&scope, 1, Duration::from_secs(1), &control)
            .await
            .unwrap()
            .claims
            .is_empty()
    );
    assert_eq!(health.health().recovery, Phase::Healthy);
    let target = Token(Target::new(scope.clone(), "a").unwrap());
    let other = Token(Target::new(scope, "b").unwrap());
    fail(&health, target.target());
    store
        .finish(&other, Completion::Converged, &control)
        .await
        .unwrap();
    store
        .finish(&target, Completion::Suspended { failures: 1 }, &control)
        .await
        .unwrap();
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Permanent)
    );
    provider.finish_fails.store(true, Ordering::Relaxed);
    assert!(
        store
            .finish(&target, Completion::Converged, &control)
            .await
            .is_err()
    );
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Permanent)
    );
    provider.finish_fails.store(false, Ordering::Relaxed);
    store
        .finish(
            &target,
            Completion::Reobserve(Duration::from_secs(1)),
            &control,
        )
        .await
        .unwrap();
    assert_eq!(health.health().recovery, Phase::Healthy);
    assert_eq!(health.health().phases().count(), 2);
}

#[tokio::test]
async fn failures_are_owner_scoped_and_overflow_requires_a_new_process_window() {
    let scope = scope("script");
    let health = Readiness::new(scope.clone(), false, false);
    let other = Readiness::new(
        Scope::new(scope.tenant(), "enrollment").unwrap(),
        false,
        false,
    );
    let provider = Provider::default();
    let store = ObservedStore::new(&provider, &health);
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&Clock, Duration::from_secs(1), &cancel);
    for id in 0..1001 {
        let target = Target::new(scope.clone(), id.to_string()).unwrap();
        fail(&health, &target);
        fail(&other, &target);
    }
    assert_eq!(other.health().recovery, Phase::Initializing);
    store
        .claim_due(&scope, 1, Duration::from_secs(1), &control)
        .await
        .unwrap();
    for id in 0..1001 {
        store
            .finish(
                &Token(Target::new(scope.clone(), id.to_string()).unwrap()),
                Completion::Converged,
                &control,
            )
            .await
            .unwrap();
    }
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Invariant)
    );
    let restarted = Readiness::new(scope, false, false);
    assert_eq!(restarted.health().recovery, Phase::Initializing);
}

#[test]
fn durable_input_recovery_clears_only_its_own_attempt_failure() {
    let scope = scope("execution");
    let health = Readiness::new(scope.clone(), false, true);
    let inputs = Target::new(scope.clone(), "inputs").unwrap();
    let operation = Target::new(scope, "operation").unwrap();
    fail(&health, &inputs);
    fail(&health, &operation);
    health.inputs(Err(ErrorKind::Permanent));
    assert_eq!(health.health().unresolved_attempts, 2);
    health.inputs(Ok(()));
    assert_eq!(health.health().inputs, Some(Phase::Healthy));
    assert_eq!(health.health().unresolved_attempts, 1);
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Permanent)
    );
}
