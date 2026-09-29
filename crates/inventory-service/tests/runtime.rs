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
    assert!(!readiness.ready());
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
    let scope =
        crate::device::scope(tenant, Uuid::new_v4(), "mdm.windows", Uuid::new_v4()).unwrap();
    assert!(LifecycleGrant::verify(authority, scope.clone()).is_err());
    assert!(ReadGrant::verify(authority, scope).is_err());
    token.cancel();
    assert!(JournalReadGrant::verify(authority, tenant).is_err());
}
