use super::*;
use rss_observation::{JournalReadGrant, LifecycleGrant, ReadGrant};
use uuid::Uuid;
#[test]
fn journal_permission_is_independent_and_readiness_requires_a_running_worker() {
    let tenant = TenantId::parse(&Uuid::new_v4().to_string()).unwrap();
    let token = CancellationToken::new();
    let authority = JournalAuthority {
        tenant,
        token: &token,
    };
    ensure_authority(&authority, tenant, &token);
    let readiness = Readiness::default();
    readiness.initialized.store(true, Ordering::Release);
    assert!(!readiness.health().is_ready());
}
fn ensure_authority(authority: &JournalAuthority<'_>, tenant: TenantId, token: &CancellationToken) {
    assert!(JournalReadGrant::verify(authority, tenant).is_ok());
    assert!(
        JournalReadGrant::verify(
            authority,
            TenantId::parse(&Uuid::new_v4().to_string()).unwrap()
        )
        .is_err()
    );
    let scope = crate::device::scope(
        rss_mdm_install_support::StorageProfile::Mdm,
        tenant,
        &rss_mdm_agent_wire::DeviceId::new_v4(),
        "mdm.windows",
        Uuid::new_v4(),
    )
    .unwrap();
    assert!(LifecycleGrant::verify(authority, scope.clone()).is_err());
    assert!(ReadGrant::verify(authority, scope).is_err());
    token.cancel();
    assert!(JournalReadGrant::verify(authority, tenant).is_err());
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test owns the fixed monotonic origin"
)]
fn startup_and_pass_budgets_have_independent_cutoffs() {
    struct Fixed(Instant);
    impl rss_observation::Clock for Fixed {
        fn now(&self) -> Instant {
            self.0
        }
    }
    let origin = Instant::now();
    let policy = Policy::new(
        Duration::from_secs(30),
        Duration::from_secs(1),
        Duration::from_secs(5),
        64,
        64 * 1024 * 1024,
        64,
        rss_observation::Batch::MAX_ENCODED_BYTES,
        64,
    )
    .unwrap();
    let clock = Clock::new(Arc::new(Fixed(origin)), policy);
    assert_eq!(clock.startup_cutoff(), Duration::from_secs(30));
    assert_eq!(clock.deadline().instant(), origin + Duration::from_secs(1));
}

#[test]
fn expiry_and_absence_never_manufacture_projection_evidence() {
    use rss_observation::LookupOutcome;
    let expired = DeliveryStatus::from_lookup(LookupOutcome::Expired, false, true);
    assert!(matches!(expired.receipt, ReceiptStatus::Expired));
    assert_eq!(expired.projection, ProjectionStatus::Unconfirmed);
    let applied = DeliveryStatus::from_lookup(LookupOutcome::Expired, true, true);
    assert!(matches!(applied.receipt, ReceiptStatus::Expired));
    assert_eq!(applied.projection, ProjectionStatus::Projected);
    let waiting = DeliveryStatus::from_lookup(LookupOutcome::NotFound, false, true);
    assert!(matches!(waiting.receipt, ReceiptStatus::NotFound));
    assert_eq!(waiting.projection, ProjectionStatus::PendingReceipt);
    assert!(matches!(
        DeliveryStatus::NO_BATCH.receipt,
        ReceiptStatus::NoBatch
    ));
}
