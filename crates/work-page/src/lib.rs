//! Bounded traversal of the product workers' ordered discovery pages.
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    num::NonZeroUsize,
    time::Duration,
};
use tokio::{sync::Notify, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

/// Each key has at most one active batch. An unfinished batch can outlive its discovery
/// round. A notification or periodic scan can therefore admit newly arrived independent work.
/// The owner supplies both the durable work and the delay until its next useful check.
#[allow(
    clippy::disallowed_methods,
    reason = "process-owned monotonic worker deadlines"
)]
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
        if stop.is_cancelled() {
            break;
        }
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
            let result = tokio::select! { biased;
                () = stop.cancelled() => break,
                result = page(after) => result,
            };
            match result {
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
        let _outcome = result.expect("owned worker batch panicked during drain");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    // The causal assertions do not depend on a particular throughput or latency.
    #[tokio::test]
    async fn slow_first_key_allows_cross_page_and_late_work_then_drains_on_stop() {
        let stop = CancellationToken::new();
        let release = Arc::new(Notify::new());
        let notify = Arc::new(Notify::new());
        let arrived = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(std::sync::Mutex::new(BTreeSet::new()));
        let (sent, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let worker = {
            let (stop, release, notify, arrived, finished) = (
                stop.clone(),
                release.clone(),
                notify.clone(),
                arrived.clone(),
                finished.clone(),
            );
            tokio::spawn(async move {
                run(
                    NonZeroUsize::new(2).unwrap(),
                    Duration::from_secs(60),
                    &stop,
                    &notify,
                    |after: Option<u32>| {
                        let mut rows: Vec<_> = (1..=33)
                            .filter(|v| {
                                after.is_none_or(|key| *v > key)
                                    && !finished.lock().unwrap().contains(v)
                            })
                            .take(32)
                            .collect();
                        if arrived.load(Ordering::Acquire)
                            && after.is_none()
                            && !finished.lock().unwrap().contains(&0)
                        {
                            rows.insert(0, 0);
                            rows.truncate(32);
                        }
                        std::future::ready(Ok(rows))
                    },
                    |key, _| {
                        let release = release.clone();
                        let sent = sent.clone();
                        let finished = finished.clone();
                        async move {
                            if key == 1 {
                                sent.send((key, false)).unwrap();
                                release.notified().await;
                            }
                            assert!(finished.lock().unwrap().insert(key));
                            sent.send((key, true)).unwrap();
                            Ok(Duration::from_secs(60))
                        }
                    },
                    |_| {},
                )
                .await;
            })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut blocked, mut second_page) = (false, false);
            while !(blocked && second_page) {
                match seen.recv().await.unwrap() {
                    (1, false) => blocked = true,
                    (33, true) => second_page = true,
                    (1, true) => panic!("released early"),
                    _ => {}
                }
            }
            arrived.store(true, Ordering::Release);
            notify.notify_one();
            while seen.recv().await.unwrap() != (0, true) {}
            stop.cancel();
            assert!(!worker.is_finished());
            release.notify_one();
            worker.await.unwrap();
            assert_eq!(finished.lock().unwrap().len(), 34);
        })
        .await
        .expect("pending work should finish while first binding remains blocked");
    }
}
