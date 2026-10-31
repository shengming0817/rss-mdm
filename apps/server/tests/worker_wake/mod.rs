use super::*;
use futures::FutureExt;
#[tokio::test(start_paused = true)]
async fn idle_wait_preserves_early_hints_and_recovers_lost_notifications() {
    let signals = Signals::default();
    let stop = CancellationToken::new();
    let notify = signals.get(Work::Inventory);
    // A commit between the work scan and registering the waiter retains one permit.
    for _ in 0..1000 {
        signals.received("inventory");
    }
    assert!(wait(notify, &stop, None).now_or_never().is_some());
    let idle = wait(notify, &stop, None);
    tokio::pin!(idle);
    assert!(idle.as_mut().now_or_never().is_none());
    tokio::time::advance(RECOVERY - Duration::from_millis(1)).await;
    assert!(idle.as_mut().now_or_never().is_none());
    tokio::time::advance(Duration::from_millis(1)).await;
    idle.await;
    let earlier = wait(notify, &stop, Some(Duration::from_millis(50)));
    tokio::pin!(earlier);
    assert!(earlier.as_mut().now_or_never().is_none());
    tokio::time::advance(Duration::from_millis(50)).await;
    earlier.await;
    stop.cancel();
    assert!(wait(notify, &stop, None).now_or_never().is_some());
}
