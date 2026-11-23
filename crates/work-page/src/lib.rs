//! Bounded traversal of the product workers' ordered discovery pages.
pub mod capacity;
pub mod external;
pub mod reconcile;
pub mod scheduler;

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
    let result: Result<(), std::convert::Infallible> = run_fallible(
        capacity,
        idle,
        stop,
        notify,
        (group, |after| {
            let future = page(after);
            async move { future.await.map_err(|()| Failure::Retry) }
        }),
        |key, _admission| {
            let future = batch(key);
            async move { future.await.map_err(|()| Failure::Retry) }
        },
        observed,
    )
    .await;
    match result {
        Ok(()) => {}
        Err(never) => match never {},
    }
}

/// A transient failure retains the durable cursor or the key's retry delay.
/// A fatal result stops new admissions and is returned after owned work drains.
pub enum Failure<E = std::convert::Infallible> {
    Retry,
    Fatal(E),
}

#[allow(
    clippy::disallowed_methods,
    reason = "process-owned monotonic worker deadlines"
)]
pub async fn run_fallible<K, G, R, P, F, E>(
    capacity: NonZeroUsize,
    idle: Duration,
    stop: &CancellationToken,
    notify: &Notify,
    (group, page): (impl Fn(K) -> G, impl Fn(Option<K>) -> P),
    batch: impl Fn(K, CancellationToken) -> F,
    observed: impl Fn(bool),
) -> Result<(), E>
where
    K: Copy + Ord + Send + 'static,
    G: Copy + Ord,
    R: Into<Page<K>>,
    P: Future<Output = Result<R, Failure<E>>>,
    F: Future<Output = Result<Duration, Failure<E>>> + Send + 'static,
    E: Send + 'static,
{
    run_limited(
        capacity,
        idle,
        stop,
        notify,
        (|key: &K| [(group(*key), 1)], page),
        batch,
        observed,
    )
    .await
}

/// Check every quota before spawning the job. A saturated group advances the page cursor
/// and is reconsidered when one of its active members completes.
#[allow(
    clippy::disallowed_methods,
    reason = "process-owned monotonic worker deadlines"
)]
pub async fn run_limited<K, G, L, R, P, F, E>(
    capacity: NonZeroUsize,
    idle: Duration,
    stop: &CancellationToken,
    notify: &Notify,
    (quotas, page): (impl Fn(&K) -> L, impl Fn(Option<K>) -> P),
    batch: impl Fn(K, CancellationToken) -> F,
    observed: impl Fn(bool),
) -> Result<(), E>
where
    K: Clone + Ord + Send + 'static,
    G: Ord,
    L: IntoIterator<Item = (G, usize)>,
    R: Into<Page<K>>,
    P: Future<Output = Result<R, Failure<E>>>,
    F: Future<Output = Result<Duration, Failure<E>>> + Send + 'static,
    E: Send + 'static,
{
    let admission = stop.child_token();
    let mut fatal = None;
    let retry = Duration::from_secs(5);
    let mut active = BTreeSet::new();
    let mut groups = BTreeMap::<G, (usize, K)>::new();
    // A promoted waiter keeps its original turn when another quota blocks its admission.
    let mut deferred = BTreeMap::<G, (bool, u128, K)>::new();
    let mut sequence = 0u128;
    let mut pending_page = None;
    let mut first_scan_finished = false;
    let mut first_batches = BTreeSet::new();
    let mut tasks = JoinSet::<(K, Result<Duration, Failure<E>>)>::new();
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
        let free = active.len() < capacity.get();
        if scanning && free && queued.is_empty() && pending_page.is_none() {
            pending_page = Some(Box::pin(page(after.clone())));
        }
        tokio::select! {
            biased;
            () = stop.cancelled() => break,
            Some(result) = tasks.join_next(), if !active.is_empty() => {
                let (key, result) = result.expect("owned worker batch panicked");
                active.remove(&key);
                first_batches.remove(&key);
                let mut released = Vec::new();
                for (group, _) in quotas(&key) {
                    let count = groups.get_mut(&group).expect("active group");
                    count.0 -= 1;
                    if count.0 == 0 { groups.remove(&group); }
                    if let Some((_, turn, waiting))=deferred.remove(&group) {
                        released.push((turn, waiting));
                        wake = Instant::now();
                    }
                }
                released.sort_unstable();
                for (turn, waiting) in released.into_iter().rev() {
                    queued.push_front((waiting, Some(turn)));
                }
                let delay = match result {
                    Ok(delay) => {
                        failures.remove(&key);
                        delay.min(idle)
                    }
                    Err(Failure::Fatal(error)) => {fatal = Some(error); break;}
                    Err(Failure::Retry) => {
                        failures.insert(key.clone());
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
            ()=std::future::ready(()), if free && !queued.is_empty() => {
                let (key, turn)=queued.pop_front().expect("queued candidate");
                unseen.remove(&key);
                if let Some(at) = due.get(&key).copied()
                    && at > Instant::now()
                {
                    wake = wake.min(at);
                    continue;
                }
                if active.contains(&key) {
                    continue;
                }
                if let Some((blocked, _)) = quotas(&key)
                    .into_iter()
                    .find(|(group, limit)| groups.get(group).map_or(0, |(count,_)| *count) >= *limit)
                {
                    let last=&groups[&blocked].1;
                    let promoted = turn.is_some();
                    let turn = turn.unwrap_or_else(|| {sequence += 1; sequence});
                    let entry = deferred.entry(blocked);
                    match entry {
                        std::collections::btree_map::Entry::Vacant(slot) => {slot.insert((promoted,turn,key));}
                        std::collections::btree_map::Entry::Occupied(mut slot) => {
                            let (other_promoted, other_turn, other) = slot.get();
                            // Fresh discoveries rotate past the last admission. Handoffs take
                            // precedence over rediscovery and keep FIFO order across quota changes.
                            let replace = if promoted || *other_promoted {
                                promoted && (!other_promoted || turn < *other_turn)
                            } else {
                                (&key <= last,&key) < (other <= last,other)
                            };
                            if replace { slot.insert((promoted,turn,key)); }
                        }
                    }
                    continue;
                }
                for (group, _) in quotas(&key) {
                    let entry = groups.entry(group).or_insert_with(||(0,key.clone()));
                    entry.0 += 1; entry.1=key.clone();
                }
                active.insert(key.clone());
                if !first_scan_finished {
                    first_batches.insert(key.clone());
                }
                let attempt = batch(key.clone(), admission.clone());
                tasks.spawn(async move { (key, attempt.await) });

            }
            result=async {pending_page.as_mut().expect("active discovery").await}, if pending_page.is_some() => {
                pending_page=None;
            match result.map(Into::into) {
                Ok(Page { rows, .. }) if !rows.is_empty() => {
                    after = rows.last().cloned();
                    queued.extend(rows.into_iter().map(|key| (key, None)));
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
                Err(Failure::Retry) => discovery_retry = Some(Instant::now() + retry),
                Err(Failure::Fatal(error)) => {
                    fatal = Some(error);
                    break;
                }
            }
            let failed = discovery_retry.is_some() || !failures.is_empty();
            if failed || (first_scan_finished && first_batches.is_empty()) {
                observed(failed);
            }
            scanning = false;
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
                if discovery_retry.take().is_none() {
                    unseen = due.keys().cloned().collect();
                    after = None;
                }
                scanning = true;
                wake = Instant::now() + idle;
            }
        }
    }
    drop(pending_page);
    admission.cancel();
    while let Some(result) = tasks.join_next().await {
        let (_, outcome) = result.expect("owned worker batch panicked during drain");
        if let Err(Failure::Fatal(error)) = outcome {
            fatal.get_or_insert(error);
        }
    }
    fatal.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn a_saturated_group_hands_its_slot_to_a_waiter_during_page_io() {
        let stop = CancellationToken::new();
        let release = CancellationToken::new();
        let reading = CancellationToken::new();
        let (tx, mut started) = tokio::sync::mpsc::unbounded_channel();
        let notify = Notify::new();
        let work = run_limited(
            NonZeroUsize::new(3).unwrap(),
            Duration::from_secs(60),
            &stop,
            &notify,
            (
                |_: &u32| [(0, 1)],
                |after| {
                    let reading = reading.clone();
                    async move {
                        if after.is_some() {
                            reading.cancel();
                            return std::future::pending().await;
                        }
                        Ok(vec![1, 2])
                    }
                },
            ),
            |key, _| {
                let release = release.clone();
                let tx = tx.clone();
                async move {
                    tx.send(key).unwrap();
                    if key == 1 {
                        release.cancelled().await;
                    }
                    Ok(Duration::ZERO)
                }
            },
            |_| {},
        );
        let proof = async {
            reading.cancelled().await;
            assert_eq!(started.recv().await, Some(1));
            release.cancel();
            assert_eq!(started.recv().await, Some(2));
            stop.cancel();
        };
        let (result, ()) =
            tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(work, proof) })
                .await
                .unwrap();
        let result: Result<(), std::convert::Infallible> = result;
        result.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_turn_survives_a_change_of_saturated_quota() {
        let stop = CancellationToken::new();
        let notify = Notify::new();
        let (tx, mut started) = tokio::sync::mpsc::unbounded_channel();
        let work = run_limited(
            NonZeroUsize::new(2).unwrap(),
            Duration::from_secs(60),
            &stop,
            &notify,
            (
                |key: &u8| [(if *key == 1 { 1 } else { 2 }, 1), (3, 1)],
                |after| {
                    std::future::ready(Ok((1..=3)
                        .filter(|key| after.is_none_or(|a| *key > a))
                        .collect::<Vec<_>>()))
                },
            ),
            |key, _| {
                let tx = tx.clone();
                async move {
                    tx.send(key).unwrap();
                    tokio::time::sleep(Duration::from_secs(6)).await;
                    Ok(Duration::from_secs(5))
                }
            },
            |_| {},
        );
        let proof = async {
            for _ in 0..5 {
                if started.recv().await == Some(3) {
                    stop.cancel();
                    return;
                }
            }
            panic!("third publication starved behind retries");
        };
        let (result, ()) = tokio::join!(work, proof);
        let result: Result<(), std::convert::Infallible> = result;
        result.unwrap();
    }

    #[tokio::test]
    async fn cancellation_releases_discovery_resources_before_draining() {
        let stop = CancellationToken::new();
        let notify = Notify::new();
        let reading = CancellationToken::new();
        let permit = Arc::new(tokio::sync::Semaphore::new(1));
        let work = run_limited(
            NonZeroUsize::new(2).unwrap(),
            Duration::from_secs(60),
            &stop,
            &notify,
            (
                |_: &u8| [(1, 1)],
                |after| {
                    let (permit, reading) = (permit.clone(), reading.clone());
                    async move {
                        if after.is_some() {
                            let _connection = permit.acquire().await.unwrap();
                            reading.cancel();
                            return std::future::pending().await;
                        }
                        Ok(vec![1])
                    }
                },
            ),
            |_, admission| {
                let permit = permit.clone();
                async move {
                    admission.cancelled().await;
                    let _connection = permit.acquire().await.unwrap();
                    Ok(Duration::ZERO)
                }
            },
            |_| {},
        );
        let proof = async {
            reading.cancelled().await;
            stop.cancel();
        };
        let (result, ()) =
            tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(work, proof) })
                .await
                .unwrap();
        let result: Result<(), std::convert::Infallible> = result;
        result.unwrap();
    }

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
