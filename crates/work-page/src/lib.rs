//! Bounded traversal of the product workers' ordered discovery pages.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    num::NonZeroUsize,
    time::Duration,
};
use tokio::{sync::Notify, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

/// A discovery page can report a durable deadline even when it has no due rows.
pub struct Page<K> {
    pub rows: Vec<K>,
    pub next: Option<Duration>,
}
impl<K> From<Vec<K>> for Page<K> {
    fn from(rows: Vec<K>) -> Self {
        Self { rows, next: None }
    }
}

/// Each key has at most one active batch. An unfinished batch can outlive its discovery
/// round. A notification or periodic scan can therefore admit newly arrived independent work.
/// The owner supplies both the durable work and the delay until its next useful check.
pub async fn run<K, P, F>(
    capacity: NonZeroUsize,
    idle: Duration,
    stop: &CancellationToken,
    notify: &Notify,
    page: impl Fn(Option<K>) -> P,
    batch: impl Fn(K) -> F,
    observed: impl Fn(bool),
) where
    K: Copy + Ord + Send + 'static,
    P: Future<Output = Result<Vec<K>, ()>>,
    F: Future<Output = Result<Duration, ()>> + Send + 'static,
{
    run_grouped(
        capacity,
        idle,
        stop,
        notify,
        (std::convert::identity, page),
        batch,
        observed,
    )
    .await;
}

/// Admit independent claim attempts for one durable binding. Each position
/// stays live until its batch drains. A peer position can refill released
/// item capacity while that batch still owns a slow head. The database
/// cursor remains the owner's key; positions exist only inside this process.
pub async fn run_partitioned<K, G, P, F>(
    (capacity, positions): (NonZeroUsize, NonZeroUsize),
    idle: Duration,
    stop: &CancellationToken,
    notify: &Notify,
    (tenant, page): (impl Fn(K) -> G, impl Fn(Option<K>) -> P),
    batch: impl Fn(K) -> F,
    observed: impl Fn(bool),
) where
    K: Copy + Ord + Send + 'static,
    G: Copy + Ord,
    P: Future<Output = Result<Vec<K>, ()>>,
    F: Future<Output = Result<Duration, ()>> + Send + 'static,
{
    run_grouped(
        capacity,
        idle,
        stop,
        notify,
        (
            |(key, position)| (tenant(key), position),
            |after: Option<(K, usize)>| {
                let rows = page(after.map(|(key, _)| key));
                async move {
                    let rows = rows.await?;
                    Ok(rows
                        .into_iter()
                        .flat_map(|key| (0..positions.get()).map(move |position| (key, position)))
                        .collect::<Vec<_>>())
                }
            },
        ),
        |(key, _)| batch(key),
        observed,
    )
    .await;
}

/// A group occupies at most one slot, so multiple keys sharing a tenant resource
/// cannot exclude other tenants. Rows still advance the owner's ordered cursor.
#[allow(
    clippy::disallowed_methods,
    reason = "process-owned monotonic worker deadlines"
)]
pub async fn run_grouped<K, G, R, P, F>(
    capacity: NonZeroUsize,
    idle: Duration,
    stop: &CancellationToken,
    notify: &Notify,
    (group, page): (impl Fn(K) -> G, impl Fn(Option<K>) -> P),
    batch: impl Fn(K) -> F,
    observed: impl Fn(bool),
) where
    K: Copy + Ord + Send + 'static,
    G: Copy + Ord,
    R: Into<Page<K>>,
    P: Future<Output = Result<R, ()>>,
    F: Future<Output = Result<Duration, ()>> + Send + 'static,
{
    let retry = Duration::from_secs(5);
    let mut active = BTreeSet::new();
    let mut groups = BTreeSet::new();
    let mut deferred = BTreeSet::new();
    let mut first_scan_finished = false;
    let mut first_batches = BTreeSet::new();
    let mut tasks = JoinSet::new();
    let mut queued = VecDeque::new();
    let mut after = None;
    let mut scanning = true;
    let mut discovery_retry = None;
    let mut due = BTreeMap::<K, Instant>::new();
    let mut failures = BTreeSet::new();
    let mut unseen = BTreeSet::new();
    let mut wake = Instant::now() + idle;
    loop {
        if stop.is_cancelled() {
            break;
        }
        if scanning && active.len() < capacity.get() {
            if let Some(key) = queued.pop_front() {
                unseen.remove(&key);
                if let Some(at) = due.get(&key).copied()
                    && at > Instant::now()
                {
                    wake = wake.min(at);
                    continue;
                }
                let owner = group(key);
                if active.contains(&key) {
                    continue;
                }
                if !groups.insert(owner) {
                    deferred.insert(owner);
                    continue;
                }
                active.insert(key);
                if !first_scan_finished {
                    first_batches.insert(key);
                }
                let attempt = batch(key);
                tasks.spawn(async move { (key, attempt.await) });
                continue;
            }
            let result = tokio::select! { biased;
                () = stop.cancelled() => break,
                result = page(after) => result,
            };
            match result.map(Into::into) {
                Ok(Page { rows, .. }) if !rows.is_empty() => {
                    after = rows.last().copied();
                    queued = rows.into();
                    continue;
                }
                Ok(Page { next, .. }) => {
                    first_scan_finished = true;
                    if let Some(delay) = next {
                        wake = wake.min(Instant::now() + delay);
                    }
                    discovery_retry = None;
                    for key in &unseen {
                        if !active.contains(key) {
                            due.remove(key);
                            failures.remove(key);
                        }
                    }
                }
                Err(()) => discovery_retry = Some(Instant::now() + retry),
            }
            let failed = discovery_retry.is_some() || !failures.is_empty();
            if failed || (first_scan_finished && first_batches.is_empty()) {
                observed(failed);
            }
            scanning = false;
        }
        tokio::select! {
            biased;
            () = stop.cancelled() => break,
            Some(result) = tasks.join_next(), if !active.is_empty() => {
                let (key, result) = result.expect("owned worker batch panicked");
                active.remove(&key);
                first_batches.remove(&key);
                let owner = group(key);
                groups.remove(&owner);
                if deferred.remove(&owner) {
                    wake = Instant::now();
                }
                let delay = match result {
                    Ok(delay) => {
                        failures.remove(&key);
                        delay.min(idle)
                    }
                    Err(()) => {
                        failures.insert(key);
                        retry
                    }
                };
                let at = Instant::now() + delay;
                due.insert(key, at);
                wake = wake.min(at);
                let failed = discovery_retry.is_some() || !failures.is_empty();
                if failed || (first_scan_finished && first_batches.is_empty()) {
                    observed(failed);
                }
            }
            hint = async {
                if let Some(at) = discovery_retry {
                    tokio::time::sleep_until(at).await;
                    return false;
                }
                tokio::select! {
                    () = notify.notified() => true,
                    () = tokio::time::sleep_until(wake) => false,
                }
            }, if !scanning && active.len() < capacity.get() => {
                if hint {
                    // Hints can announce new work before a previously observed deadline.
                    // Faulted bindings still observe their own retry delay.
                    due.retain(|key, _| failures.contains(key));
                }
                unseen = due.keys().copied().collect();
                after = None;
                scanning = true;
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
                    |key| {
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
    #[tokio::test(start_paused = true)]
    async fn failed_binding_recovers_while_a_peer_is_still_running() {
        let stop = CancellationToken::new();
        let release = Arc::new(Notify::new());
        let notify = Arc::new(Notify::new());
        let ready = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (health, mut changes) = tokio::sync::mpsc::unbounded_channel();
        let running = {
            let ready = ready.clone();
            let (stop, release, notify, attempts) = (
                stop.clone(),
                release.clone(),
                notify.clone(),
                attempts.clone(),
            );
            tokio::spawn(async move {
                run(
                    NonZeroUsize::new(2).unwrap(),
                    Duration::from_millis(500),
                    &stop,
                    &notify,
                    |after| {
                        std::future::ready(Ok(
                            if ready.load(Ordering::Acquire) && after.is_none() {
                                vec![1, 2]
                            } else {
                                vec![]
                            },
                        ))
                    },
                    |key| {
                        let (release, attempts) = (release.clone(), attempts.clone());
                        async move {
                            if key == 1 {
                                release.notified().await;
                            }
                            if key == 2 && attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                                return Err(());
                            }
                            Ok(Duration::from_secs(60))
                        }
                    },
                    |failed| {
                        let _sent = health.send(failed);
                    },
                )
                .await;
            })
        };
        assert_eq!(changes.recv().await, Some(false));
        ready.store(true, Ordering::Release);
        notify.notify_one();
        while changes.recv().await != Some(true) {}
        notify.notify_one();
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        while changes.recv().await != Some(false) {}
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        stop.cancel();
        release.notify_one();
        running.await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn initial_health_waits_for_the_first_batches() {
        let stop = CancellationToken::new();
        let notify = Notify::new();
        let release = Arc::new(Notify::new());
        let (health, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let finished_page = Notify::new();
        let run = run(
            NonZeroUsize::new(2).unwrap(),
            Duration::from_secs(5),
            &stop,
            &notify,
            |after| {
                if after.is_some() {
                    finished_page.notify_one();
                }
                std::future::ready(Ok(if after.is_none() {
                    vec![1, 2]
                } else {
                    Vec::new()
                }))
            },
            |key| {
                let release = release.clone();
                async move {
                    if key == 1 {
                        release.notified().await;
                        return Err(());
                    }
                    Ok(Duration::from_secs(5))
                }
            },
            |failed| {
                health.send(failed).unwrap();
            },
        );
        tokio::pin!(run);
        tokio::select! { () = &mut run => panic!("worker exited"), () = finished_page.notified() => {} }
        assert!(observed.try_recv().is_err());
        release.notify_one();
        tokio::select! { () = &mut run => panic!("worker exited"), state = observed.recv() => assert_eq!(state, Some(true)) }
        stop.cancel();
        run.await;
    }
}
