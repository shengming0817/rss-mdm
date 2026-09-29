use super::*;
#[tokio::test]
async fn critical_listener_exit_retains_name_and_cleanup_outcome() {
    for name in ["mdm-enrollment-tls", "mdm-management-tls"] {
        let mut scope = LifecycleScope::<(), ProcessError, std::io::Error>::try_new(
            TotalDrainBudget::new(Duration::from_secs(2)).unwrap(),
            Arc::new(RuntimeTimer),
        )
        .unwrap();
        let outcome = scope
            .drive(
                |startup| {
                    Box::pin(async move {
                        let mut launch = startup.commit();

                        let (task, _) =
                            rss_runtime::ManagedTask::prepare(name, Duration::from_secs(1));
                        launch.stage_task_with_token(
                            task.into_registration(|_| async {
                                Err(ShutdownError::new(std::io::Error::other(
                                    "synthetic-secret",
                                )))
                            })
                            .critical(),
                        );
                        launch.finish();
                        std::future::pending().await
                    })
                },
                std::future::pending(),
            )
            .await
            .unwrap();
        let diagnostic = finish(outcome.exit(), false).unwrap_err().to_string();
        assert!(diagnostic.contains(name) && diagnostic.contains("cleanup_failed=true"));
        assert!(!diagnostic.contains("synthetic-secret"));
    }
}
#[test]
fn assembly_failures_identify_windows_inputs() {
    for (issue, stage) in [
        (ConfigIssue::EnrollmentCa, "startup.windows_ca"),
        (ConfigIssue::ProtocolKey, "startup.protocol_key"),
        (ConfigIssue::NativeTls, "startup.native_tls"),
    ] {
        assert!(
            assembly_error(Error::Configuration(issue))
                .to_string()
                .starts_with(stage)
        );
    }
}
