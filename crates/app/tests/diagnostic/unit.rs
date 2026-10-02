use super::*;
#[test]
fn operator_unknown_commit_preserves_safe_recovery_class() {
    assert!(
        ProcessError::at(
            "authorization.initialize",
            Error::Flow(rss_mdm_flow_service::Error::RollbackFailed)
        )
        .to_string()
        .contains("rollback_unconfirmed; retry_same_operation")
    );
    assert!(
        ProcessError::at(
            "authorization.initialize",
            Error::Flow(rss_mdm_flow_service::Error::CommitUnknown)
        )
        .to_string()
        .contains("retry_same_operation")
    );
    assert_eq!(
        ProcessError::at(
            "authorization.initialize",
            Error::Flow(rss_mdm_flow_service::Error::Conflict)
        )
        .to_string(),
        "authorization.initialize: conflict"
    );
    assert_eq!(
        ProcessError::at(
            "authorization.initialize",
            Error::Flow(rss_mdm_flow_service::Error::Malformed)
        )
        .to_string(),
        "authorization.initialize: malformed_input"
    );
}
