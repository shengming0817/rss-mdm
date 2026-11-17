use rss_mdm_recovery_observation::{ObservedStore, Phase, Readiness};
use rss_reconcile::*;
use std::{
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
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
    scan_budget: AtomicU32,
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
        scan_budget: u32,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<ClaimBatch<Token>, Error> {
        self.scan_budget.store(scan_budget, Ordering::Relaxed);
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
    let health = Readiness::new(scope.reconciler(), true, false);
    let provider = Provider::default();
    let store = ObservedStore::new(&provider, &health);
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&Clock, Duration::from_secs(1), &cancel);
    provider.scan_fails.store(true, Ordering::Relaxed);
    assert!(
        store
            .claim_due(&scope, 1, 64, Duration::from_secs(1), &control)
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
            .claim_due(&unrelated, 1, 64, Duration::from_secs(1), &control)
            .await
            .is_err()
    );
    let other_tenant = Scope::new(
        rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000002").unwrap(),
        scope.reconciler(),
    )
    .unwrap();
    store
        .claim_due(&other_tenant, 1, 64, Duration::from_secs(1), &control)
        .await
        .unwrap();
    health.discovery(Ok(())); // An empty discovery page cannot erase the failed tenant scan.
    health.relay_round(Ok(()));
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Transient)
    );
    assert!(
        store
            .claim_due(&scope, 1, 64, Duration::from_secs(1), &control)
            .await
            .unwrap()
            .claims
            .is_empty()
    );
    assert_eq!(health.health().recovery, Phase::Healthy);
    health.relay_scope(&scope, 1, Err(ErrorKind::Transient));
    health.relay_scope(&other_tenant, 1, Ok(()));
    health.relay_scope(&scope, 2, Ok(()));
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Transient)
    );
    health.relay_scope(&scope, 1, Ok(()));
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
    let health = Readiness::new(scope.reconciler(), false, false);
    let other = Readiness::new("enrollment", false, false);
    let provider = Provider::default();
    let store = ObservedStore::new(&provider, &health);
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&Clock, Duration::from_secs(1), &cancel);
    for id in 0..1001 {
        let target = Target::new(scope.clone(), id.to_string()).unwrap();
        fail(&health, &target);
        fail(&other, &target);
    }
    assert_eq!(other.health().recovery, Phase::Unobserved);
    store
        .claim_due(&scope, 1, 64, Duration::from_secs(1), &control)
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
    let restarted = Readiness::new(scope.reconciler(), false, false);
    assert_eq!(restarted.health().recovery, Phase::Unobserved);
}

#[test]
fn durable_input_recovery_clears_only_its_own_attempt_failure() {
    let scope = scope("execution");
    let health = Readiness::new(scope.reconciler(), false, true);
    let inputs = Target::new(scope.clone(), "inputs").unwrap();
    let operation = Target::new(scope, "operation").unwrap();
    fail(&health, &inputs);
    fail(&health, &operation);
    health.inputs(&inputs, Err(ErrorKind::Permanent));
    assert_eq!(health.health().unresolved_attempts, 2);
    health.inputs(&inputs, Ok(()));
    assert_eq!(health.health().inputs, Some(Phase::Healthy));
    assert_eq!(health.health().unresolved_attempts, 1);
    assert_eq!(
        health.health().recovery,
        Phase::Failed(ErrorKind::Permanent)
    );
}

#[tokio::test]
async fn scan_budget_reaches_the_provider_without_losing_empty_scan_observation() {
    let scope = scope("capacity");
    let health = Readiness::new(scope.reconciler(), false, false);
    let provider = Provider::default();
    let store = ObservedStore::new(&provider, &health);
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&Clock, Duration::from_secs(1), &cancel);
    let batch = store
        .claim_due(&scope, 1024, 4096, Duration::from_secs(1), &control)
        .await
        .unwrap();
    assert!(batch.claims.is_empty());
    assert!(!batch.more);
    assert_eq!(provider.scan_budget.load(Ordering::Relaxed), 4096);
}
