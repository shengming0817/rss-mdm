//! Each command owner rotates bindings independently within the command pool's relay budget.
use crate::delivery_capacity::{Capacity, Slot};
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use std::{
    collections::BTreeMap,
    future::Future,
    num::NonZeroUsize,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
type Key = (Uuid, i64);
const IDLE: Duration = Duration::from_secs(5);

pub(super) struct Relay {
    capacity: Arc<Capacity>,
    storage: StorageIdentity,
    stop: CancellationToken,
    failure: OnceLock<rss_runtime::ShutdownError>,
    owners: Mutex<Vec<Arc<Notify>>>,
}
impl Relay {
    pub(super) fn new(
        parallelism: usize,
        storage: StorageIdentity,
        stop: &CancellationToken,
    ) -> Arc<Self> {
        let capacity = NonZeroUsize::new(parallelism).expect("positive relay budget");
        Arc::new(Self {
            capacity: Capacity::commands(capacity),
            storage,
            stop: stop.child_token(),
            failure: OnceLock::new(),
            owners: Mutex::default(),
        })
    }
    fn wake_owners(&self) {
        for owner in self.owners.lock().expect("owner notifications").iter() {
            owner.notify_one();
        }
    }
    async fn run<E, P, B>(
        self: &Arc<Self>,
        name: &'static str,
        page: impl Fn(Option<Key>) -> P,
        batch: impl Fn(ExecutionBinding, Vec<Slot>) -> B + Send + Sync + 'static,
        observe: impl Fn(ExecutionBinding, &Result<usize, E>) + Send + Sync + 'static,
    ) where
        E: std::error::Error + Send + Sync + 'static,
        P: Future<Output = Result<Vec<Key>, E>>,
        B: Future<Output = Result<usize, E>> + Send + 'static,
    {
        let notify = Arc::new(Notify::new());
        self.owners
            .lock()
            .expect("owner notifications")
            .push(notify.clone());
        let batch = Arc::new(batch);
        let observe = Arc::new(observe);
        let rounds = Arc::new(Mutex::new(BTreeMap::<Key, Round>::new()));
        rss_mdm_work_page::run_partitioned(
            (self.capacity.total(), self.capacity.batches_per_binding()),
            IDLE,
            &self.stop,
            &notify,
            (
                |key: Key| key.0,
                |after| {
                    let query = page(after);
                    async move {
                        query.await.map_err(|error| {
                            let event = serde_json::json!({
                                "event": "command_relay_discovery_failed",
                                "owner": name,
                                "reason": error.to_string()
                            });
                            eprintln!("{event}");
                        })
                    }
                },
            ),
            |key| {
                let (relay, rounds, batch, observe) =
                    (self.clone(), rounds.clone(), batch.clone(), observe.clone());
                async move {
                    let Some(slots) = relay.capacity.acquire(name, key.0, &relay.stop).await else {
                        return Ok(IDLE);
                    };
                    let tenant = rss_request_context::TenantId::parse(&key.0.to_string())
                        .expect("UUID tenant");
                    let epoch = Epoch::new(key.1).map_err(|error| {
                        let _ = relay.failure.set(rss_runtime::ShutdownError::new(error));
                        relay.stop.cancel();
                    })?;
                    let binding = ExecutionBinding::new(relay.storage, tenant, epoch);
                    {
                        let mut running = rounds.lock().expect("relay observations");
                        let round = running.entry(key).or_default();
                        if round.failed || relay.stop.is_cancelled() {
                            return Ok(IDLE);
                        }
                        round.active += 1;
                    }
                    let result = batch(binding, slots).await;
                    let mut running = rounds.lock().expect("relay observations");
                    let round = running.get_mut(&key).expect("active binding");
                    round.active -= 1;
                    if result.is_err() || !round.failed {
                        observe(binding, &result);
                    }
                    round.failed |= result.is_err();
                    if round.active == 0 {
                        running.remove(&key);
                    }
                    result
                        .map(|count| if count > 0 { Duration::ZERO } else { IDLE })
                        .map_err(|_| ())
                }
            },
            |_| {},
        )
        .await;
    }
}

#[derive(Default)]
struct Round {
    active: usize,
    failed: bool,
}

async fn settle<E>(
    claims: Vec<impl Future<Output = Result<(), E>>>,
    slots: Vec<Slot>,
) -> Result<usize, E> {
    let count = claims.len();
    assert!(count <= slots.len(), "owner exceeded the admitted batch");
    let work = claims
        .into_iter()
        .zip(slots)
        .map(|(claim, slot)| async move {
            let _slot = slot;
            claim.await
        });
    // Poll every admitted effect through settlement, including after a sibling fails.
    for outcome in futures::future::join_all(work).await {
        outcome?;
    }
    Ok(count)
}

// The owners retain their concrete error types, epoch validation and scope health.
macro_rules! owner {
    ($name:ident, $owner:ty) => {
        pub(super) async fn $name(relay: &Arc<Relay>, owner: Arc<$owner>) {
            let source = owner.clone();
            let health = owner.clone();
            relay
                .run(
                    stringify!($name),
                    |after| {
                        let owner = source.clone();
                        async move { owner.relay_page(after).await }
                    },
                    move |binding, slots| {
                        let owner = owner.clone();
                        async move {
                            let limit = NonZeroUsize::new(slots.len()).expect("admitted heads");
                            let claims = owner.claim_relay(binding, limit).await?;
                            settle(claims, slots).await
                        }
                    },
                    move |binding, result| health.observe_relay(binding, result),
                )
                .await;
        }
    };
}
owner!(device, rss_mdm_device_service::control::Service);
owner!(policy, rss_mdm_policy_service::worker::PolicyWork);
owner!(script, rss_mdm_script_service::worker::Worker);
owner!(
    inventory,
    rss_mdm_inventory_service::collection::execution::worker::Worker
);
owner!(
    software,
    rss_mdm_software_service::deployment::SoftwareService
);
owner!(
    installation,
    rss_mdm_registration_service::installation::Service
);
owner!(
    enrollment,
    rss_mdm_registration_service::enrollment::tasks::worker::Worker
);
owner!(
    device_access,
    rss_mdm_device_access_postgres::device_access::execution::worker::Worker
);
owner!(
    credentials,
    rss_mdm_recovery_credentials::tasks::worker::Worker
);
owner!(
    native_credentials,
    rss_mdm_recovery_credentials::native::Service
);
#[expect(
    clippy::too_many_arguments,
    reason = "fixed concrete owners share one relay and shutdown budget"
)]
pub(crate) fn registration(
    policy: Arc<rss_mdm_policy_service::worker::PolicyWork>,
    execution: Arc<rss_mdm_device_service::control::Service>,
    scripts: Arc<rss_mdm_script_service::worker::Worker>,
    collections: Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    software: Arc<rss_mdm_software_service::deployment::SoftwareService>,
    installation: Arc<rss_mdm_registration_service::installation::Service>,
    enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::worker::Worker>,
    access: Arc<rss_mdm_device_access_postgres::device_access::execution::worker::Worker>,
    credentials: Vec<Arc<rss_mdm_recovery_credentials::tasks::worker::Worker>>,
    native_credentials: Option<Arc<rss_mdm_recovery_credentials::native::Service>>,
    parallelism: usize,
    storage: StorageIdentity,
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("mdm-task-relay", Duration::from_secs(20));
    task.into_registration(move |stop| async move {
        let relay = Relay::new(parallelism, storage, &stop);
        let mut owners: Vec<futures::future::BoxFuture<'_, ()>> = vec![
            Box::pin(device(&relay, execution)),
            Box::pin(self::policy(&relay, policy)),
            Box::pin(script(&relay, scripts)),
            Box::pin(inventory(&relay, collections)),
            Box::pin(self::software(&relay, software)),
            Box::pin(self::installation(&relay, installation)),
            Box::pin(self::enrollment(&relay, enrollment)),
            Box::pin(device_access(&relay, access)),
        ];
        for worker in credentials {
            owners.push(Box::pin(self::credentials(&relay, worker)));
        }
        if let Some(worker) = native_credentials {
            owners.push(Box::pin(self::native_credentials(&relay, worker)));
        }
        {
            let work = futures::future::join_all(owners);
            tokio::pin!(work);
            loop {
                tokio::select! { biased;
                    _ = &mut work => break,
                    () = notify.notified() => relay.wake_owners(),
                }
            }
        }
        match Arc::into_inner(relay)
            .expect("all relay owners drained")
            .failure
            .into_inner()
        {
            Some(error) => Err(error),
            None => Ok(()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn owner_receives_a_hint_sent_after_its_empty_snapshot() {
        let stop = CancellationToken::new();
        let relay = Relay::new(2, StorageIdentity::new([1; 16], [2; 16]).unwrap(), &stop);
        let release = Notify::new();
        let scanned = Notify::new();
        let seen = std::cell::Cell::new(false);
        let rescan = Notify::new();
        let work = relay.run(
            "test",
            |_| {
                let first = !seen.replace(true);
                let (scanned, release, rescan) = (&scanned, &release, &rescan);
                async move {
                    if first {
                        scanned.notify_one();
                        release.notified().await;
                    } else {
                        rescan.notify_one();
                    }
                    Ok::<_, std::io::Error>(Vec::new())
                }
            },
            |_, _| std::future::ready(Ok(0)),
            |_, _| {},
        );
        tokio::pin!(work);
        tokio::select! { () = &mut work => panic!("relay exited"), () = scanned.notified() => {} }
        relay.wake_owners();
        release.notify_one();
        // With paused time, the ready branch must precede the periodic scan.
        tokio::select! { biased; () = &mut work => panic!("relay exited"), () = rescan.notified() => {}, () = std::future::ready(()) => panic!("hint lost") }
        stop.cancel();
        work.await;
    }
}
