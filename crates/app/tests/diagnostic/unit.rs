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

#[test]
fn actual_owner_diagnostics_retain_closed_failure_categories() {
    for (error, expected) in [
        (
            Error::Content(rss_mdm_content_service::Error::Configuration),
            "Content(Configuration)",
        ),
        (
            Error::Content(rss_mdm_content_service::Error::Storage),
            "Content(Storage)",
        ),
        (
            Error::Content(rss_mdm_content_service::Error::Invariant),
            "Content(Invariant)",
        ),
        (
            Error::Authorization(rss_mdm_authorization_service::Error::Conflict),
            "Conflict",
        ),
        (
            Error::Authorization(rss_mdm_authorization_service::Error::Unauthorized),
            "Unauthorized",
        ),
        (
            Error::Authorization(rss_mdm_authorization_service::Error::Deadline),
            "Deadline",
        ),
        (
            Error::Execution(rss_mdm_execution_service::Error::Unavailable(
                rss_mdm_execution_service::Failure::NativeInputIntegrity,
            )),
            "ExecutionDependency(NativeInputIntegrity)",
        ),
    ] {
        assert!(
            ProcessError::at("owner.test", error)
                .to_string()
                .contains(expected)
        );
    }
}
