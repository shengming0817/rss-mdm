use crate::{Error, Failure};

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
