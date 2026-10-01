use crate::{Error, Failure};

#[tokio::test]
async fn readiness_requires_both_confirmed_rounds_and_live_task() {
    use super::super::health::{Phase, Readiness};
    let readiness = Readiness::default();
    assert!(!readiness.health().is_ready());
    let (start, status) =
        rss_runtime::ManagedTask::prepare("execution-health", std::time::Duration::from_secs(2));
    readiness.bind(status);
    assert!(!readiness.health().is_ready());
    let task = start.spawn_detached(
        tokio_util::sync::CancellationToken::new(),
        |cancel| async move {
            cancel.cancelled().await;
            Ok(())
        },
    );
    assert!(!readiness.health().is_ready());
    readiness.scan(Ok(()));
    assert!(!readiness.health().is_ready());
    readiness.relay(Ok(()));
    assert!(readiness.health().is_ready());
    readiness.scan(Err(rss_reconcile::ErrorKind::Transient));
    assert!(!readiness.health().is_ready());
    assert!(matches!(readiness.health().recovery, Phase::Failed(_)));
    readiness.scan(Ok(()));
    assert!(readiness.health().is_ready());
    readiness.relay(Err(rss_reconcile::ErrorKind::CommitUnknown));
    assert!(!readiness.health().is_ready());
    readiness.relay(Ok(()));
    assert!(readiness.health().is_ready());
    readiness.stop();
    readiness.scan(Ok(()));
    readiness.relay(Ok(()));
    assert!(!readiness.health().is_ready());
    task.shutdown().await.unwrap();
    assert!(!readiness.health().is_ready());
}

#[tokio::test]
async fn readiness_never_survives_task_completion_error_panic_or_abort() {
    use super::super::health::Readiness;
    for mode in 0..4 {
        let readiness = Readiness::default();
        let (start, status) = rss_runtime::ManagedTask::prepare(
            "execution-terminal",
            std::time::Duration::from_secs(2),
        );
        readiness.bind(status.clone());
        readiness.scan(Ok(()));
        readiness.relay(Ok(()));
        let task = start.spawn_detached(
            tokio_util::sync::CancellationToken::new(),
            move |_| async move {
                match mode {
                    0 => Ok(()),
                    1 => Err(rss_runtime::ShutdownError::new(std::io::Error::other(
                        "failure",
                    ))),
                    2 => panic!("fixture panic"),
                    _ => std::future::pending().await,
                }
            },
        );
        if mode == 3 {
            drop(task);
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), status.wait_stopped())
            .await
            .unwrap();
        assert!(!readiness.health().is_ready());
    }
}

#[test]
fn relay_diagnostic_preserves_complete_message_identity() {
    let error = Error::Unavailable(Failure::CommandStorage);
    for message_id in [
        "action.11111111-1111-4111-8111-111111111111",
        "dispatch.22222222-2222-4222-8222-222222222222",
    ] {
        let value = super::relay_diagnostic_value("accept", Some(message_id), &error);
        assert_eq!(value["messageId"], message_id);
        assert_eq!(value["reason"], "transient");
    }
    assert!(super::relay_diagnostic_value("claim", None, &error)["messageId"].is_null());
}

#[tokio::test]
async fn unbounded_control_is_cancellable() {
    let timer = super::Timer::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = rss_reconcile::Control::new(&timer, std::time::Duration::MAX, &cancel);
    let (outcome, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            control.run(std::future::pending::<
                std::result::Result<(), rss_reconcile::Error>,
            >()),
            async {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                cancel.cancel();
            }
        )
    })
    .await
    .expect("unbounded worker control must remain cancellable");
    assert_eq!(
        outcome.unwrap_err().kind(),
        rss_reconcile::ErrorKind::Cancelled
    );
}
