use rss_contract::Timepoint;
use rss_mdm_policy_postgres::{core::*, *};
use rss_request_context::TenantId;
fn tenant() -> TenantId {
    TenantId::parse("11111111-1111-1111-1111-111111111111").unwrap()
}
#[test]
fn fresh_plan_is_an_installation_fact_not_a_reused_digest() {
    let key = PolicyId::new(tenant(), "policy").unwrap();
    let draft = Aggregate::draft(key);
    assert!(!draft.plan_is_fresh());
    assert_eq!(draft.storage_revision(), 0);
    assert_eq!(draft.policy().revision(), 0);
    let request = Request {
        id: RequestId::new(tenant(), "create").unwrap(),
        expected_storage_revision: 0,
        as_of: Timepoint::try_from(1).unwrap(),
        command: Command::Create {
            policy: draft.policy().key().clone(),
        },
    };
    assert_eq!(request.policy(), draft.policy().key());
}
