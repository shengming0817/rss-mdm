//! A scripted storage boundary reports the claim's original observation time and
//! the completion actually acknowledged, just like Scheduler.
#![allow(clippy::disallowed_methods, reason = "paused Tokio clock")]
use super::*;
use rss_reconcile::{ActualState, DesiredState};
use rss_request_context::TenantId;

const SHORT: Duration = Duration::from_millis(20);
const LATE: Duration = Duration::from_millis(50);

struct Item {
    target: Target,
    first: bool,
}
impl Claim for Item {
    fn target(&self) -> &Target {
        &self.target
    }
    fn failures(&self) -> u32 {
        0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Reschedule,
    EarlyEmpty,
    NewWork,
    SlowCursor,
    LockedCursor,
    SharedTail,
    LockedTarget,
}

enum PageConstraint {
    AfterTicket(&'static str),
    SkipLocked(&'static str),
}

struct Store {
    start: Instant,
    due: Mutex<BTreeMap<String, (Instant, bool)>>,
    scans: Mutex<Vec<(Duration, Vec<String>)>>,
    scenario: Scenario,
    tail_pending: std::sync::atomic::AtomicBool,
    next_page: Mutex<Option<PageConstraint>>,
}
impl DurableStore for Store {
    type Claim = Item;
    async fn wake<T: Timer>(
        &self,
        _: &Target,
        _: &ResourceSet,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        unreachable!()
    }
    async fn bind_resources<T: Timer>(
        &self,
        _: &Target,
        _: &ResourceSet,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        unreachable!()
    }
    async fn release<T: Timer>(&self, _: &Item, _: &Control<'_, T>) -> Result<(), Error> {
        unreachable!()
    }
    async fn renew<T: Timer>(
        &self,
        _: &Item,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        unreachable!()
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        _: u32,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<ClaimBatch<Item>, Error> {
        let started = Instant::now();
        let elapsed = started - self.start;
        // The tail of the delayed cursor sweep cannot revisit the earlier ticket.
        let tail = self.tail_pending.swap(false, Ordering::SeqCst);
        let locked = self.scenario == Scenario::LockedCursor
            && elapsed == SHORT
            && !self
                .scans
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == SHORT);
        let constraint = self.next_page.lock().unwrap().take();
        let claims: Vec<_> = {
            let mut due = self.due.lock().unwrap();
            let names: Vec<_> = due
                .iter()
                .filter(|(_, (at, _))| !tail && !locked && *at <= started)
                .filter(|(name, _)| match constraint {
                    Some(PageConstraint::AfterTicket(ticket)) => name.as_str() > ticket,
                    Some(PageConstraint::SkipLocked(entity)) => name.as_str() != entity,
                    None => true,
                })
                .take(limit)
                .map(|(name, _)| name.clone())
                .collect();
            let claims = names
                .iter()
                .map(|name| Item {
                    target: Target::new(scope.clone(), name.clone()).unwrap(),
                    first: due.remove(name).unwrap().1,
                })
                .collect();
            self.scans.lock().unwrap().push((elapsed, names));
            claims
        };
        let slow_head =
            self.scenario == Scenario::SlowCursor && elapsed == Duration::from_millis(5);
        if slow_head {
            self.tail_pending.store(true, Ordering::SeqCst);
            tokio::time::sleep_until(self.start + Duration::from_millis(25)).await;
        }
        let more = self.scans.lock().unwrap().len() == 1 || slow_head;
        scanned(scope, started, more, claims.iter().map(Claim::target));
        Ok(ClaimBatch { claims, more })
    }
    async fn finish<T: Timer>(
        &self,
        claim: &Item,
        mut completion: Completion,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        // This owner committed a longer defer than the callback requested.
        if claim.first && claim.target.entity() == "late" {
            assert_eq!(completion, Completion::Deferred(SHORT));
            completion = Completion::Deferred(LATE);
        }
        match completion {
            Completion::Reobserve(after) | Completion::Deferred(after) => {
                self.due.lock().unwrap().insert(
                    claim.target.entity().to_owned(),
                    (Instant::now() + after, false),
                );
            }
            Completion::Converged => {}
            other => panic!("unexpected completion {other:?}"),
        }
        settled(&claim.target, Some(completion));
        Ok(())
    }
}
impl Reconciler<Item> for Store {
    type State = ();
    async fn observe<T: Timer>(
        &self,
        claim: &Item,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<ReconcileDiff<()>>, Error> {
        if self.scenario == Scenario::Reschedule && claim.first {
            return Ok(ReconcileStep::Deferred(Duration::from_secs(86_400)));
        }
        if claim.target.entity() == "z-peer" {
            // A nonempty tail with no immediate convergence-driven follow-up.
            return Ok(ReconcileStep::Deferred(Duration::from_secs(60)));
        }
        if claim.first && claim.target.entity() == "late" {
            return Ok(ReconcileStep::Deferred(SHORT));
        }
        let actual = if claim.first {
            ActualState::missing()
        } else {
            ActualState::present(())
        };
        Ok(ReconcileStep::Ready(ReconcileDiff::between(
            DesiredState::present(()),
            actual,
        )))
    }
    async fn apply<T: Timer>(
        &self,
        _: &Item,
        _: ReconcileDiff<()>,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<()>, Error> {
        Ok(ReconcileStep::Ready(()))
    }
}
async fn verify_schedule(scenario: Scenario) {
    let start = Instant::now();
    let store = Arc::new(Store {
        start,
        due: Mutex::new(BTreeMap::from([
            ("short".into(), (start, true)),
            ("late".into(), (start, true)),
        ])),
        scans: Mutex::default(),
        scenario,
        tail_pending: Default::default(),
        next_page: Default::default(),
    });
    let id = Uuid::from_u128(1);
    let scope = Scope::new(TenantId::parse(&id.to_string()).unwrap(), "planning").unwrap();
    let capacity = Capacity::new(NonZeroUsize::new(2).unwrap());
    let policy = test_policy(2);
    let stop = CancellationToken::new();
    let notify = Notify::new();
    let worker = run(
        &capacity,
        policy,
        &stop,
        &notify,
        |after| std::future::ready(Ok(if after.is_none() { vec![id] } else { vec![] })),
        {
            let store = store.clone();
            move |_, grant, stop| {
                let (store, scope) = (store.clone(), scope.clone());
                async move { batch((&*store, &*store), grant, &scope, policy, &stop, |_| {}).await }
            }
        },
    );
    let proof = async {
        tokio::time::sleep_until(start + Duration::from_millis(5)).await;
        {
            let scans = store.scans.lock().unwrap();
            assert_eq!(scans.len(), 2, "more must produce exactly one extra page");
            assert!(scans[1].1.is_empty());
        }
        if scenario == Scenario::NewWork {
            store
                .due
                .lock()
                .unwrap()
                .insert("new".into(), (Instant::now(), false));
        }
        notify.notify_one();
        if matches!(scenario, Scenario::SharedTail | Scenario::LockedTarget) {
            tokio::time::sleep_until(start + Duration::from_millis(6)).await;
            store
                .due
                .lock()
                .unwrap()
                .insert("z-peer".into(), (start + SHORT, false));
            *store.next_page.lock().unwrap() = Some(match scenario {
                Scenario::SharedTail => PageConstraint::AfterTicket("short"),
                _ => PageConstraint::SkipLocked("short"),
            });
        }
        tokio::time::sleep_until(start + LATE + Duration::from_millis(1)).await;
        assert_eq!(store.scans.lock().unwrap()[2].0, Duration::from_millis(5));
        let short_due = if scenario == Scenario::SlowCursor {
            Duration::from_millis(25)
        } else {
            SHORT
        };
        let history = store.scans.lock().unwrap().clone();
        let nonempty: Vec<_> = history
            .iter()
            .flat_map(|(time, names)| names.iter().map(|name| (*time, name.as_str())))
            .collect();
        let mut expected = vec![(Duration::ZERO, "late"), (Duration::ZERO, "short")];
        if scenario == Scenario::NewWork {
            expected.push((Duration::from_millis(5), "new"));
        }
        if matches!(scenario, Scenario::SharedTail | Scenario::LockedTarget) {
            let first_due_page = history.iter().find(|(at, _)| *at == SHORT).unwrap();
            assert_eq!(first_due_page.1, ["z-peer"]);
            expected.push((SHORT, "z-peer"));
        }
        expected.extend([(short_due, "short"), (LATE, "late")]);
        assert_eq!(nonempty, expected);
        if scenario == Scenario::SlowCursor {
            assert!(
                history
                    .iter()
                    .any(|(at, names)| *at == short_due && names.is_empty()),
                "cursor tail must finish before the fresh pass recovers the skipped ticket"
            );
        }
        tokio::time::sleep_until(start + LATE + RECOVERY - Duration::from_millis(1)).await;
        assert_eq!(
            store.scans.lock().unwrap().len(),
            history.len(),
            "idle must not spin"
        );
        tokio::time::sleep_until(start + LATE + RECOVERY + Duration::from_millis(1)).await;
        assert_eq!(
            store.scans.lock().unwrap().len(),
            history.len() + 1,
            "idle recovery scan"
        );
        stop.cancel();
    };
    let (result, ()) = tokio::join!(worker, proof);
    result.unwrap();
}

#[tokio::test(start_paused = true)]
async fn early_empty_notification_preserves_both_settlements_after_more() {
    verify_schedule(Scenario::EarlyEmpty).await;
}
#[tokio::test(start_paused = true)]
async fn notification_claims_new_work_before_the_original_deadline() {
    verify_schedule(Scenario::NewWork).await;
}
#[tokio::test(start_paused = true)]
async fn an_in_flight_empty_page_cannot_consume_a_later_deadline() {
    verify_schedule(Scenario::SlowCursor).await;
}

#[tokio::test(start_paused = true)]
async fn a_locked_empty_terminal_page_gets_a_fresh_scan() {
    verify_schedule(Scenario::LockedCursor).await;
}

#[tokio::test(start_paused = true)]
async fn a_peers_cursor_can_skip_a_due_ticket_on_a_nonempty_tail() {
    verify_schedule(Scenario::SharedTail).await;
}

#[tokio::test(start_paused = true)]
async fn a_page_can_claim_a_peer_while_the_due_target_is_locked() {
    verify_schedule(Scenario::LockedTarget).await;
}

#[tokio::test(start_paused = true)]
async fn one_tenants_scan_backoff_allows_a_peers_notifications() {
    let start = Instant::now();
    let a = Uuid::from_u128(1);
    let b = Uuid::from_u128(2);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let stop = CancellationToken::new();
    let notify = Notify::new();
    let capacity = Capacity::new(NonZeroUsize::new(2).unwrap());
    let worker = run(
        &capacity,
        test_policy(2),
        &stop,
        &notify,
        |after| std::future::ready(Ok(if after.is_none() { vec![a, b] } else { vec![] })),
        {
            let calls = calls.clone();
            move |tenant, grant, _| {
                calls.lock().unwrap().push((tenant, start.elapsed()));
                async move {
                    if tenant == a && start.elapsed() < RECOVERY {
                        return Err(Error::new(ErrorKind::Transient));
                    }
                    grant.round.claimed(false);
                    Ok(())
                }
            }
        },
    );
    let proof = async {
        tokio::time::sleep_until(start + SHORT).await;
        notify.notify_one();
        tokio::time::sleep_until(start + RECOVERY + Duration::from_millis(1)).await;
        let calls = calls.lock().unwrap();
        let attempts = |id| {
            calls
                .iter()
                .filter_map(|(tenant, at)| (*tenant == id).then_some(*at))
                .collect::<Vec<_>>()
        };
        assert_eq!(attempts(a), [Duration::ZERO, RECOVERY]);
        assert_eq!(attempts(b), [Duration::ZERO, SHORT]);
        stop.cancel();
    };
    let (result, ()) = tokio::join!(worker, proof);
    result.unwrap();
}

#[path = "reschedule.rs"]
mod reschedule;
