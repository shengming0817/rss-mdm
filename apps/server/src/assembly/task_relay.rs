//! Each command owner rotates bindings independently within the command pool's relay budget.
use std::{
    future::Future,
    num::NonZeroUsize,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
type Key = (Uuid, i64);
const IDLE: Duration = Duration::from_secs(5);

pub(super) struct Relay {
    capacity: NonZeroUsize,
    permits: Arc<Semaphore>,
    stop: CancellationToken,
    failure: OnceLock<rss_runtime::ShutdownError>,
    owners: Mutex<Vec<Arc<Notify>>>,
}
impl Relay {
    pub(super) fn new(parallelism: usize, stop: &CancellationToken) -> Arc<Self> {
        let capacity = NonZeroUsize::new(parallelism.clamp(1, 2)).expect("positive relay budget");
        Arc::new(Self {
            capacity,
            permits: Arc::new(Semaphore::new(capacity.get())),
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
        batch: impl Fn(Key) -> B,
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
        rss_mdm_work_page::run(
            self.capacity,
            IDLE,
            &self.stop,
            &notify,
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
            |key| {
                let relay = self.clone();
                let work = batch(key);
                async move {
                    let _permit = tokio::select! { biased;
                        () = relay.stop.cancelled() => return Ok(IDLE),
                        permit = relay.permits.acquire() => permit.expect("relay budget is live"),
                    };
                    match work.await {
                        Ok(0) => Ok(IDLE),
                        Ok(_) => Ok(Duration::ZERO),
                        Err(error) => {
                            let _ = relay.failure.set(rss_runtime::ShutdownError::new(error));
                            relay.stop.cancel();
                            Err(())
                        }
                    }
                }
            },
            |_| {},
        )
        .await;
    }
}

// The owners retain their concrete error types, epoch validation and scope health.
macro_rules! owner {
    ($name:ident, $owner:ty) => {
        pub(super) async fn $name(relay: &Arc<Relay>, owner: Arc<$owner>) {
            relay
                .run(
                    stringify!($name),
                    |after| {
                        let owner = owner.clone();
                        async move { owner.relay_page(after).await }
                    },
                    |key| {
                        let owner = owner.clone();
                        async move { owner.relay_scope(key).await }
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
    notify: Arc<tokio::sync::Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("mdm-task-relay", Duration::from_secs(20));
    task.into_registration(move |stop| async move {
        let relay = Relay::new(parallelism, &stop);
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
        let relay = Relay::new(2, &stop);
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
            |_| std::future::ready(Ok(0)),
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
