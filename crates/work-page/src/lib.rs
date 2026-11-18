//! Bounded traversal of the product workers' ordered discovery pages.
use std::{collections::{BTreeSet, VecDeque}, future::Future, num::NonZeroUsize, time::Duration};
use tokio::{sync::Notify, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

/// Each key has at most one active batch. An unfinished batch can outlive its discovery
/// round. A notification or periodic scan can therefore admit newly arrived independent work.
/// The owner supplies both the durable work and the delay until its next useful check.
pub async fn run<K, P, F>(
    capacity: NonZeroUsize,
    idle: Duration,
    stop: &CancellationToken,
    notify: &Notify,
    page: impl Fn(Option<K>) -> P,
    batch: impl Fn(K, NonZeroUsize) -> F,
    observed: impl Fn(bool),
) where
    K: Copy + Ord + Send + 'static,
    P: Future<Output = Result<Vec<K>, ()>>,
    F: Future<Output = Result<Duration, ()>> + Send + 'static,
{
    let mut active = BTreeSet::new();
    let mut tasks = JoinSet::new();
    let mut queued = VecDeque::new();
    let mut after = None;
    let mut scanning = true;
    let mut failed = false;
    let mut wake = Instant::now() + idle;
    loop {
        if stop.is_cancelled() { break; }
        if scanning && active.len() < capacity.get() {
            if let Some(key) = queued.pop_front() {
                if active.insert(key) {
                    let slots = if queued.is_empty() && active.len() == 1 {
                        capacity
                    } else {
                        NonZeroUsize::MIN
                    };
                    let attempt = batch(key, slots);
                    tasks.spawn(async move { (key, attempt.await) });
                }
                continue;
            }
            match page(after).await {
                Ok(rows) if !rows.is_empty() => {
                    after = rows.last().copied();
                    queued = rows.into();
                    continue;
                }
                Ok(_) => {}
                Err(()) => {
                    failed = true;
                    observed(true);
                    wake = wake.min(Instant::now() + Duration::from_secs(5));
                }
            }
            scanning = false;
        }
        if !scanning && active.is_empty() {
            observed(failed);
        }
        tokio::select! {
            biased;
            () = stop.cancelled() => break,
            Some(result) = tasks.join_next(), if !active.is_empty() => {
                let (key, result) = result.expect("owned worker batch panicked");
                active.remove(&key);
                let delay = result.unwrap_or_else(|()| {
                    failed = true;
                    observed(true);
                    Duration::from_secs(5)
                });
                wake = wake.min(Instant::now() + delay);
            }
            () = async {
                tokio::select! {
                    () = notify.notified() => {},
                    () = tokio::time::sleep_until(wake) => {},
                }
            }, if !scanning && active.len() < capacity.get() => {
                after = None;
                scanning = true;
                if active.is_empty() { failed = false; }
                wake = Instant::now() + idle;
            }
        }
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("owned worker batch panicked during drain");
    }
}
