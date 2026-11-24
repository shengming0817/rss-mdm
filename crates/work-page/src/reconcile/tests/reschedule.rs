//! Count physical claim calls after a full day of software deferral.
use super::*;

const TASKS: usize = 1000;
const DELAY: Duration = Duration::from_secs(86_400);

async fn measure(distinct: bool) -> (usize, usize) {
    let start = Instant::now();
    let tenant = Uuid::from_u128(1);
    let scope = Scope::new(TenantId::parse(&tenant.to_string()).unwrap(), "software").unwrap();
    let store = Arc::new(Store {
        start,
        due: Default::default(),
        scans: Default::default(),
        scenario: Scenario::Reschedule,
        tail_pending: Default::default(),
        next_page: Default::default(),
    });
    let peak = Arc::new(AtomicUsize::new(0));
    let stop = CancellationToken::new();
    let notify = Notify::new();
    let capacity = Capacity::new(NonZeroUsize::MIN);
    let policy = test_policy(1);
    let worker = run(
        &capacity,
        policy,
        &stop,
        &notify,
        |after| {
            std::future::ready(Ok(if after.is_none() {
                vec![tenant]
            } else {
                vec![]
            }))
        },
        {
            let store = store.clone();
            let peak = peak.clone();
            move |_, grant, stop| {
                let (store, scope, peak) = (store.clone(), scope.clone(), peak.clone());
                async move {
                    let round = grant.round.clone();
                    batch((&*store, &*store), grant, &scope, policy, &stop, |_| {}).await?;
                    peak.fetch_max(
                        round.running.lock().unwrap()[&tenant].deadlines.len(),
                        Ordering::SeqCst,
                    );
                    Ok(())
                }
            }
        },
    );
    let proof = async {
        for i in 0..TASKS {
            let entity = if distinct { i } else { 0 }.to_string();
            store
                .due
                .lock()
                .unwrap()
                .insert(entity, (Instant::now(), true));
            notify.notify_one();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let expected = if distinct { TASKS } else { 1 };
        assert_eq!(store.due.lock().unwrap().len(), expected);
        // Let recovery run just before the old deadlines. The 1s measurement
        // window then contains no five-second idle scan.
        tokio::time::advance(DELAY - start.elapsed() - Duration::from_millis(2)).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        let offset = store.scans.lock().unwrap().len();
        tokio::time::sleep_until(start + DELAY + Duration::from_millis(TASKS as u64)).await;
        let scans = store.scans.lock().unwrap();
        let mut claimed = 0;
        let mut empty = 0;
        for (at, names) in &scans[offset..] {
            if names.is_empty() && *at < DELAY + Duration::from_millis(TASKS as u64 - 1) {
                empty += 1;
            }
            for name in names {
                let i = if distinct {
                    name.parse::<usize>().unwrap()
                } else {
                    TASKS - 1
                };
                assert_eq!(*at, DELAY + Duration::from_millis(i as u64));
                claimed += 1;
            }
        }
        assert_eq!(claimed, expected);
        stop.cancel();
        empty
    };
    let (result, empty) = tokio::join!(worker, proof);
    result.unwrap();
    (peak.load(Ordering::SeqCst), empty)
}

#[tokio::test(start_paused = true)]
async fn long_software_replacements_and_independent_targets() {
    let one = measure(false).await;
    let many = measure(true).await;
    eprintln!(
        "software reschedules (peak hints, empty claims before final due): one={one:?} independent={many:?}"
    );
    assert_eq!(many.0, TASKS);
    assert_eq!(one, (1, 0));
}

fn position(
    tenant: Uuid,
    position: usize,
    running: Arc<Mutex<BTreeMap<Uuid, Tenant>>>,
) -> Arc<Round> {
    running
        .lock()
        .unwrap()
        .entry(tenant)
        .or_default()
        .active
        .insert(position);
    Arc::new(Round {
        tenant,
        position,
        running,
        rescan: Default::default(),
    })
}

#[tokio::test(start_paused = true)]
async fn late_ack_cannot_replace_a_local_successor_and_peer_hints_expire() {
    let id = Uuid::new_v4();
    let scope = Scope::new(TenantId::parse(&id.to_string()).unwrap(), "deployment").unwrap();
    let task = Target::new(scope.clone(), "exact").unwrap();
    let host: Arc<Mutex<BTreeMap<Uuid, Tenant>>> = Default::default();
    let other: Arc<Mutex<BTreeMap<Uuid, Tenant>>> = Default::default();
    let first = position(id, 0, host.clone());
    let successor = position(id, 1, host.clone());
    let peer = position(id, 0, other.clone());
    let start = Instant::now();
    CURRENT
        .scope((scope.clone(), peer.clone()), async {
            scanned(&scope, start, false, std::iter::once(&task));
            settled(&task, Some(Completion::Deferred(SHORT)));
        })
        .await;
    // Acknowledgements can arrive in a different order from physical commits.
    CURRENT
        .scope((scope.clone(), first.clone()), async {
            scanned(&scope, start, false, std::iter::once(&task));
        })
        .await;
    CURRENT
        .scope((scope.clone(), successor.clone()), async {
            scanned(&scope, start, false, std::iter::once(&task));
            settled(&task, Some(Completion::Converged));
        })
        .await;
    CURRENT
        .scope((scope.clone(), first), async {
            settled(&task, Some(Completion::Deferred(DELAY)));
        })
        .await;
    assert!(host.lock().unwrap()[&id].deadlines.is_empty());
    assert_eq!(other.lock().unwrap()[&id].deadlines.len(), 1);
    tokio::time::advance(SHORT).await;
    CURRENT
        .scope((scope.clone(), peer), async {
            for _ in 0..2 {
                scanned(&scope, Instant::now(), false, std::iter::empty());
            }
        })
        .await;
    assert!(other.lock().unwrap()[&id].by_entity.is_empty());
}
