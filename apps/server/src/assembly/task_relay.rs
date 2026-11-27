//! Each command owner rotates bindings independently within the command pool's relay budget.
use crate::delivery_capacity::{Capacity, Slot};
use rss_mdm_recovery_observation::RelayWork;
pub(crate) mod lanes;
pub(crate) mod projection;
use lanes::*;
use projection::Projection;
use rss_mdm_work_page::Failure as SchedulingFailure;
use rss_reconcile::ErrorKind;
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
type Key = (Uuid, i64, RelayWork);
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
    async fn run<P, B>(
        self: &Arc<Self>,
        name: &'static str,
        page: impl Fn(Option<Uuid>) -> P,
        batch: impl Fn(ExecutionBinding, Vec<Slot>, CancellationToken, RelayWork) -> B
        + Send
        + Sync
        + 'static,
    ) where
        P: Future<Output = Result<Vec<Key>, ErrorKind>>,
        B: Future<Output = Result<projection::Batch, ErrorKind>> + Send + 'static,
    {
        let notify = Arc::new(Notify::new());
        self.owners
            .lock()
            .expect("owner notifications")
            .push(notify.clone());
        let batch = Arc::new(batch);
        let result = rss_mdm_work_page::run_partitioned(
            (self.capacity.total(), self.capacity.batches_per_binding()),
            IDLE,
            &self.stop,
            &notify,
            (
                |key: Key| key.0,
                |after| {
                    let query = page(after.map(|(tenant, _, _)| tenant));
                    async move {
                        query
                            .await
                            .map(|rows| {
                                rss_mdm_work_page::Page::new(rows, None)
                                    .retain(|key| key.2 != RelayWork::Idle)
                            })
                            .map_err(|error| {
                                let event = serde_json::json!({
                                    "event": "command_relay_discovery_failed",
                                    "owner": name,
                                    "reason": format!("{error:?}")
                                });
                                eprintln!("{event}");
                                if error == ErrorKind::StorageContract {
                                    SchedulingFailure::Fatal(error)
                                } else {
                                    SchedulingFailure::Retry
                                }
                            })
                    }
                },
            ),
            |key, admission| {
                let (relay, batch) = (self.clone(), batch.clone());
                async move {
                    let Some(slots) = relay.capacity.acquire(name, key.0, &admission).await else {
                        return Ok(IDLE);
                    };
                    let tenant = rss_request_context::TenantId::parse(&key.0.to_string())
                        .expect("UUID tenant");
                    let epoch = Epoch::new(key.1).map_err(|error| {
                        let _ = relay.failure.set(rss_runtime::ShutdownError::new(error));
                        relay.stop.cancel();
                        SchedulingFailure::Fatal(ErrorKind::Invariant)
                    })?;
                    let binding = ExecutionBinding::new(relay.storage, tenant, epoch);
                    if admission.is_cancelled() {
                        return Ok(IDLE);
                    }
                    batch(binding, slots, admission, key.2)
                        .await
                        .map_err(|kind| {
                            if kind == ErrorKind::StorageContract {
                                SchedulingFailure::Fatal(kind)
                            } else {
                                SchedulingFailure::Retry
                            }
                        })
                        .and_then(projection::Batch::next_delay)
                }
            },
            |_| {},
        )
        .await;
        if let Err(kind) = result {
            eprintln!(
                "{}",
                serde_json::json!({"event":"command_relay_owner_stopped","owner":name,"reason":format!("{kind:?}")})
            );
        }
    }
}

/// An admitted slot can check one failed message before claiming more work.
/// An unavailable or uncertain read preserves the original failure.
impl Projection {
    pub(crate) async fn verify_terminal(
        &self,
        binding: ExecutionBinding,
        scope: &rss_mdm_recovery_observation::RelayScope<'_>,
    ) {
        let runtime = &self.runtime;
        let Some(probe) = scope.check() else {
            return;
        };
        // The Outbox terminal status is fenced by RSS. Both published and quarantined
        // resolve this exact uncertainty. Neither another message nor an empty page can.
        let original = probe.message();
        let Some(fingerprint) = original.fingerprint else {
            // Learning a digest doesn't establish the outcome. The next check is fenced by that digest.
            if let Some(digest) = read_fingerprint(binding, runtime, original).await {
                probe.identify(digest);
            }
            return;
        };
        let terminal = runtime.local_tx_with_context(binding,
        rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(1)),
        (binding.tenant().to_string(),original,fingerprint,self.lane.role),|args,tx| Box::pin(async move {
            tx.with_connection_context(args, |(tenant,message,digest,group),c|Box::pin(async move {
                sqlx::query_scalar::<_,String>("SELECT o.status FROM rss_transactional_messaging.outbox o WHERE o.tenant_id=$1::uuid AND o.domain=$2 AND o.message_id=$3 AND o.fingerprint=$4 AND (o.status='dead_letter' OR (o.status='published' AND EXISTS (SELECT FROM rss_transactional_messaging.inbox i WHERE i.tenant_id=o.tenant_id AND i.message_id=o.message_id AND i.consumer_group=$5 AND i.fingerprint=o.fingerprint AND i.disposition='succeeded')))")
                    .bind(tenant.as_str()).bind(message.domain.as_str()).bind(message.id.as_str()).bind(digest.as_bytes().as_slice()).bind(*group).fetch_optional(c).await
            })).await
        })).await.fold(|state|state,|_|None,|_|None,|_|None,|_|None,|_|None);
        if let Some(status) = terminal {
            if status == "dead_letter" {
                probe.dead_lettered();
            } else {
                probe.published();
            }
        }
    }
}

/// The provider's original header has a unique tenant/message ID and immutable domain and digest.
async fn read_fingerprint(
    binding: ExecutionBinding,
    runtime: &rss_transactional_messaging_postgres::PgRuntime,
    original: &rss_mdm_recovery_observation::RelayMessage,
) -> Option<rss_transactional_messaging::message::MessageFingerprint> {
    let args = (binding.tenant().to_string(), original);
    let bytes = runtime
        .local_tx_with_context(
            binding,
            rss_transactional_messaging::policy::OperationDeadline::from_remaining(Duration::from_secs(1)),
            args,
            |args, tx| Box::pin(async move {
                tx.with_connection_context(args, |(tenant, message), connection| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, Vec<u8>>(
                            "SELECT fingerprint FROM rss_transactional_messaging.outbox WHERE tenant_id=$1::uuid AND domain=$2 AND message_id=$3"
                        )
                        .bind(tenant.as_str())
                        .bind(message.domain.as_str())
                        .bind(message.id.as_str())
                        .fetch_optional(connection)
                        .await
                    })
                }).await
            }),
        )
        .await
        .fold(|row| row, |_| None, |_| None, |_| None, |_| None, |_| None)?;
    Some(
        rss_transactional_messaging::message::MessageFingerprint::from_bytes(
            bytes.try_into().ok()?,
        ),
    )
}

#[derive(Clone)]
pub(crate) enum Owner {
    Device(Arc<rss_mdm_device_service::control::Service>),
    Policy(Arc<rss_mdm_policy_service::worker::PolicyWork>),
    Script(Arc<rss_mdm_script_service::worker::Worker>),
    Inventory(Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>),
    Software(Arc<rss_mdm_software_service::deployment::SoftwareService>),
    Installation(Arc<rss_mdm_registration_service::installation::Service>),
    Enrollment(Arc<rss_mdm_registration_service::enrollment::tasks::worker::Worker>),
    Access(Arc<rss_mdm_device_access_postgres::device_access::execution::worker::Worker>),
    Credentials(Arc<rss_mdm_recovery_credentials::tasks::worker::Worker>),
    NativeCredentials(Arc<rss_mdm_recovery_credentials::native::Service>),
}
impl Owner {
    fn lane(&self) -> Lane {
        match self {
            Self::Device(_) => DEVICE,
            Self::Policy(_) => POLICY,
            Self::Script(_) => SCRIPT,
            Self::Inventory(_) => INVENTORY,
            Self::Software(_) => SOFTWARE,
            Self::Installation(_) => INSTALLATION,
            Self::Enrollment(_) => ENROLLMENT,
            Self::Access(_) => ACCESS,
            Self::NativeCredentials(_) => NATIVE_CREDENTIALS,
            Self::Credentials(w) => match w.profile() {
                rss_mdm_install_support::StorageProfile::Mdm => CREDENTIALS,
                rss_mdm_install_support::StorageProfile::Da => DA_CREDENTIALS,
            },
        }
    }
    async fn page(&self, after: Option<Uuid>) -> Result<Vec<Key>, ErrorKind> {
        match self {
            Self::Device(owner) => owner.relay_page(after).await,
            Self::Policy(owner) => owner.relay_page(after).await,
            Self::Script(owner) => owner.relay_page(after).await,
            Self::Inventory(owner) => owner.relay_page(after).await,
            Self::Software(owner) => owner.relay_page(after).await,
            Self::Installation(owner) => owner.relay_page(after).await,
            Self::Enrollment(owner) => owner.relay_page(after).await,
            Self::Access(owner) => owner.relay_page(after).await,
            Self::Credentials(owner) => owner.relay_page(after).await,
            Self::NativeCredentials(owner) => owner.relay_page(after).await,
        }
    }
    fn scope(
        &self,
        binding: ExecutionBinding,
    ) -> Option<rss_mdm_recovery_observation::RelayScope<'_>> {
        match self {
            Self::Device(owner) => owner.relay_scope(binding),
            Self::Policy(owner) => owner.relay_scope(binding),
            Self::Script(owner) => owner.relay_scope(binding),
            Self::Inventory(owner) => owner.relay_scope(binding),
            Self::Software(owner) => owner.relay_scope(binding),
            Self::Installation(owner) => owner.relay_scope(binding),
            Self::Enrollment(owner) => owner.relay_scope(binding),
            Self::Access(owner) => owner.relay_scope(binding),
            Self::Credentials(owner) => owner.relay_scope(binding),
            Self::NativeCredentials(owner) => owner.relay_scope(binding),
        }
    }
}
async fn drive(relay: &Arc<Relay>, owner: Owner, projection: Arc<Projection>) {
    let discovery = owner.clone();
    relay
        .run(
            projection.lane.owner,
            move |after| {
                let owner = discovery.clone();
                async move { owner.page(after).await }
            },
            move |binding, slots, stop, work| {
                let owner = owner.clone();
                let projection = projection.clone();
                async move {
                    let Some(scope) = owner.scope(binding) else {
                        return Ok(Default::default());
                    };
                    tokio::select! {
                        biased;
                        () = stop.cancelled() => return Ok(Default::default()),
                        () = projection.verify_terminal(binding, &scope) => {}
                    }
                    if stop.is_cancelled() || work == RelayWork::Readback {
                        return Ok(Default::default());
                    }
                    projection.poll(binding, slots, Some(&scope)).await
                }
            },
        )
        .await;
}
#[expect(
    clippy::too_many_arguments,
    reason = "fixed concrete owners share one relay and shutdown budget"
)]
pub(crate) async fn registration(
    config: &crate::config::Config,
    audit: &rss_mdm_audit_integration::AuditStore,
    protection: Arc<rss_mdm_native_protection::Protector>,
    mut resource: impl FnMut(crate::owner_storage::Resource),
    policy: Arc<rss_mdm_policy_service::worker::PolicyWork>,
    device_control: Arc<rss_mdm_device_service::control::Service>,
    scripts: Arc<rss_mdm_script_service::worker::Worker>,
    collections: Arc<rss_mdm_inventory_service::collection::execution::worker::Worker>,
    software: Arc<rss_mdm_software_service::deployment::SoftwareService>,
    installation: Arc<rss_mdm_registration_service::installation::Service>,
    enrollment: Arc<rss_mdm_registration_service::enrollment::tasks::worker::Worker>,
    access: Arc<rss_mdm_device_access_postgres::device_access::execution::worker::Worker>,
    credentials: Vec<Arc<rss_mdm_recovery_credentials::tasks::worker::Worker>>,
    native_credentials: Option<Arc<rss_mdm_recovery_credentials::native::Service>>,
    parallelism: usize,
    binding: ExecutionBinding,
    notify: Arc<tokio::sync::Notify>,
) -> Result<rss_runtime::ManagedTaskRegistration, crate::Error> {
    let mut owners = vec![
        Owner::Device(device_control),
        Owner::Policy(policy),
        Owner::Script(scripts),
        Owner::Inventory(collections),
        Owner::Software(software),
        Owner::Installation(installation),
        Owner::Enrollment(enrollment),
        Owner::Access(access),
    ];
    owners.extend(credentials.into_iter().map(Owner::Credentials));
    owners.extend(native_credentials.map(Owner::NativeCredentials));
    let mut projections = Vec::new();
    for lane in lanes::enabled(
        config.device_access.is_some(),
        config.recovery_credentials.is_some(),
    ) {
        let index = owners.iter().position(|owner| owner.lane() == lane).ok_or(
            crate::Error::Configuration(crate::ConfigIssue::BusinessDatabase),
        )?;
        let owner = owners.swap_remove(index);
        let runtime = Projection::connect(config, binding, lane)
            .await
            .inspect_err(|_| {
                eprintln!("command relay startup: role={} stage=connect", lane.role);
            })?;
        resource(crate::owner_storage::Resource::new(
            runtime.clone(),
            lane.role,
        ));
        let projection = Projection::bind(runtime, binding, audit, protection.clone(), lane)
            .await
            .inspect_err(|_| {
                eprintln!("command relay startup: role={} stage=admission", lane.role);
            })?;
        projections.push((owner, projection));
    }
    Ok(register(
        projections,
        parallelism,
        binding.storage(),
        notify,
    ))
}

pub(crate) fn register(
    projections: Vec<(Owner, Arc<Projection>)>,
    parallelism: usize,
    storage: StorageIdentity,
    notify: Arc<Notify>,
) -> rss_runtime::ManagedTaskRegistration {
    let (task, _) = rss_runtime::ManagedTask::prepare("mdm-task-relay", Duration::from_secs(20));
    task.into_registration(move |stop| async move {
        let relay = Relay::new(parallelism, storage, &stop);
        {
            let work = futures::future::join_all(
                projections
                    .into_iter()
                    .map(|(owner, projection)| drive(&relay, owner, projection)),
            );
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
        let capacity = Capacity::commands(NonZeroUsize::new(4).unwrap());
        let tenant = Uuid::new_v4();
        let stop = CancellationToken::new();
        let mdm = capacity
            .acquire(CREDENTIALS.owner, tenant, &stop)
            .await
            .unwrap();
        assert_eq!(mdm.len(), 2);
        let da = capacity.acquire(DA_CREDENTIALS.owner, tenant, &stop);
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
                    Ok::<_, ErrorKind>(Vec::new())
                }
            },
            |_, _, _, _| std::future::ready(Ok(Default::default())),
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
