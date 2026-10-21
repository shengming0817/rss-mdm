use rss_mdm_agent_wire::runtime::CurrentUserChange;
use serde_json::json;
use uuid::Uuid;
#[test]
fn current_user_changes_cannot_supply_authority_and_bound_cas() {
    let operation = Uuid::new_v4();
    let value = json!({"operationId":operation,"expectedRevision":0});
    assert!(
        serde_json::from_value::<CurrentUserChange>(value.clone())
            .unwrap()
            .validate()
            .is_ok()
    );
    for (key, extra) in [
        ("user", json!({"principalId":operation})),
        ("deviceId", json!("other")),
        ("sessionReference", json!({})),
    ] {
        let mut malformed = value.clone();
        malformed[key] = extra;
        assert!(serde_json::from_value::<CurrentUserChange>(malformed).is_err());
    }
    for (id, revision) in [(Uuid::nil(), 0), (operation, i64::MAX as u64)] {
        assert!(
            CurrentUserChange {
                operation_id: id,
                expected_revision: revision
            }
            .validate()
            .is_err()
        );
    }
}
