use super::*;
#[test]
fn operator_unknown_commit_preserves_safe_recovery_class() {
    assert!(
        ProcessError::at("authorization.initialize", Error::RollbackFailed)
            .to_string()
            .contains("rollback_unconfirmed; retry_same_operation")
    );
    assert!(
        ProcessError::at("authorization.initialize", Error::CommitUnknown)
            .to_string()
            .contains("retry_same_operation")
    );
    assert_eq!(
        ProcessError::at("authorization.initialize", Error::Conflict).to_string(),
        "authorization.initialize: conflict"
    );
    assert_eq!(
        ProcessError::at("authorization.initialize", Error::Malformed).to_string(),
        "authorization.initialize: malformed_input"
    );
}
