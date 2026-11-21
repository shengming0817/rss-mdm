//! Each command owner rotates bindings independently within the command pool's relay budget.
use crate::delivery_capacity::{Capacity, Slot};
use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
use std::{
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
    ) where
        E: std::error::Error + Send + Sync + 'static,
        P: Future<Output = Result<Vec<Key>, E>>,
        B: Future<Output = Result<usize, ()>> + Send + 'static,
    {
        let notify = Arc::new(Notify::new());
        self.owners
            .lock()
            .expect("owner notifications")
            .push(notify.clone());
        let batch = Arc::new(batch);
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
                let (relay, batch) = (self.clone(), batch.clone());
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
                    if relay.stop.is_cancelled() {
                        return Ok(IDLE);
                    }
                    batch(binding, slots)
                        .await
                        .map(|count| if count > 0 { Duration::ZERO } else { IDLE })
                }
            },
            |_| {},
        )
        .await;
    }
}

/// An admitted slot can check one failed message before claiming more work.
/// An unavailable or uncertain read preserves the original failure.
pub(crate) async fn verify_publication(
    binding: ExecutionBinding,
    probe: Option<(
        rss_mdm_recovery_observation::RelayCheck<'_>,
        &rss_transactional_messaging_postgres::PgRuntime,
        &rss_transactional_messaging_postgres::PgOutboxStore<()>,
    )>,
) {
    let Some((probe, runtime, store)) = probe else {
        return;
    };
    let published = runtime
        .local_tx_with_context(
            binding,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                Duration::from_secs(1),
            ),
            (store, &probe.message),
            |(store, message), tx| {
                Box::pin(async move {
                    store
                        .is_published(tx, &message.domain, &message.id, message.fingerprint)
                        .await
                })
            },
        )
        .await
        .fold(
            |published| published,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
        );
    if published {
        probe.published();
    }
}

async fn settle<E>(
    claims: Vec<(
        rss_mdm_recovery_observation::RelayMessage,
        impl Future<Output = Result<(), E>>,
    )>,
    slots: Vec<Slot>,
    observe: impl Fn(&rss_mdm_recovery_observation::RelayMessage, Result<(), &E>),
) -> Result<usize, ()> {
    let count = claims.len();
    assert!(count <= slots.len(), "owner exceeded the admitted batch");
    let work = claims.into_iter().zip(slots).map(|((id, claim), slot)| {
        let observe = &observe;
        async move {
            let _slot = slot;
            let result = claim.await;
            observe(&id, result.as_ref().map(|_| ()));
            result.is_ok()
        }
    });
    // Poll each effect through settlement and publish its own observation immediately.
    if futures::future::join_all(work)
        .await
        .into_iter()
        .all(|ok| ok)
    {
        Ok(count)
    } else {
        Err(())
    }
}

// The owners retain their concrete error types, epoch validation and scope health.
macro_rules! owner {
    ($name:ident, $owner:ty) => {
        owner!($name, $owner, |_: &$owner| stringify!($name));
    };
    ($name:ident, $owner:ty, $identity:expr) => {
        pub(super) async fn $name(relay: &Arc<Relay>, owner: Arc<$owner>) {
            let source = owner.clone();
            let stop = relay.stop.clone();
            relay
                .run(
                    ($identity)(owner.as_ref()),
                    |after| {
                        let owner = source.clone();
                        async move { owner.relay_page(after).await }
                    },
                    move |binding, slots| {
                        let owner = owner.clone();
                        let stop = stop.clone();
                        async move {
                            tokio::select! { biased;
                                () = stop.cancelled() => return Ok(0),
                                () = verify_publication(binding, owner.relay_check(binding)) => {}
                            }
                            if stop.is_cancelled() {
                                return Ok(0);
                            }
                            let limit = NonZeroUsize::new(slots.len()).expect("admitted heads");
                            let claims = owner.claim_relay(binding, limit).await;
                            owner.observe_relay(binding, None, claims.as_ref().map(|_| ()));
                            settle(claims.map_err(|_| ())?, slots, |id, outcome| {
                                owner.observe_relay(binding, Some(id), outcome)
                            })
                            .await
                        }
                    },
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
fn credential_owner(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    match profile {
        rss_mdm_install_support::StorageProfile::Mdm => "mdm_credentials",
        rss_mdm_install_support::StorageProfile::Da => "da_credentials",
    }
}
owner!(
    credentials,
    rss_mdm_recovery_credentials::tasks::worker::Worker,
    |worker: &rss_mdm_recovery_credentials::tasks::worker::Worker| credential_owner(
        worker.profile()
    )
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
    #[tokio::test]
    async fn da_credentials_can_acquire_the_third_tenant_slot() {
        use rss_mdm_install_support::StorageProfile::{Da, Mdm};
        let capacity = Capacity::commands(NonZeroUsize::new(4).unwrap());
        let tenant = Uuid::new_v4();
        let stop = CancellationToken::new();
        let mdm = capacity
            .acquire(credential_owner(Mdm), tenant, &stop)
            .await
            .unwrap();
        assert_eq!(mdm.len(), 2);
        let da = capacity.acquire(credential_owner(Da), tenant, &stop);
        tokio::pin!(da);
        assert!(
            matches!(futures::poll!(&mut da), std::task::Poll::Ready(Some(slots)) if slots.len() == 1)
        );
        drop(mdm);
    }

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
