use crate::{
    PgError, PgRuntime, events,
    fanout::{Eligibility, Fanout},
    transport,
};
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    error::MessagingError,
    message::MessageEnvelope,
    observability::TransactionalMessagingEmitter,
    policy::{DeliveryBudget, OperationDeadline, within},
    transport::{
        PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage,
        PublishOutcome, Publisher,
    },
};
use rss_transactional_messaging_postgres::PgOutboxStore;
use rss_transactional_messaging_runtime::relay::relay_once;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use uuid::Uuid;
struct Observed<P, T> {
    storage: rss_transactional_messaging::fence::StorageIdentity,
    discovery_pool: sqlx::PgPool,
    inner: P,
    runtime: Arc<PgRuntime>,
    timer: Arc<T>,
}
impl<P: Publisher<Vec<u8>>, T: ExecutionTimer> Publisher<Vec<u8>> for Observed<P, T> {
    type Receipt = P::Receipt;
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> PublishOutcome<Self::Receipt> {
        let failure = || {
            PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
                PublishFailureKind::Transient,
                PublishFailureStage::Admission,
                PublishFailureReason::TransportUnavailable,
            ))
        };
        let Ok(cutoff) = Deadline::from_timeout(self.timer.as_ref(), deadline.timeout()) else {
            return failure();
        };
        let Ok(id) = Uuid::parse_str(message.id().as_str()) else {
            return failure();
        };
        let tenant = message.metadata().tenant_id();
        let Ok(binding) = delivery_execution(&self.discovery_pool, self.storage, tenant, id).await
        else {
            return failure();
        };
        if within(self.timer.as_ref(), cutoff, |d| {
            record(&self.runtime, binding, id, None, d)
        })
        .await
        .ok()
        .and_then(Result::ok)
        .is_none()
        {
            return failure();
        }
        let result = match within(self.timer.as_ref(), cutoff, |d| {
            self.inner.publish(message, d)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => PublishOutcome::Ambiguous(PublishFailure::new(
                PublishFailureKind::Transient,
                PublishFailureStage::Confirm,
                PublishFailureReason::DeadlineElapsed,
            )),
        };
        let observation = match &result {
            PublishOutcome::Confirmed(_) => ("received", None, None),
            PublishOutcome::Ambiguous(f) => (
                "unknown",
                Some(f.stage().as_label()),
                Some(f.reason().as_label()),
            ),
            PublishOutcome::DefinitelyNotPublished(f) => (
                "notSent",
                Some(f.stage().as_label()),
                Some(f.reason().as_label()),
            ),
        };
        // Observation failure cannot discard HTTP receipt evidence or replace the RSS settlement.
        let _observation = within(self.timer.as_ref(), cutoff, |d| {
            record(&self.runtime, binding, id, Some(observation), d)
        })
        .await;
        result
    }
}
async fn record(
    runtime: &PgRuntime,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    id: Uuid,
    outcome: Option<(&'static str, Option<&'static str>, Option<&'static str>)>,
    deadline: OperationDeadline,
) -> Result<(), PgError> {
    runtime.local_tx(binding,deadline,move|tx|Box::pin(async move {
        let t=binding.tenant().to_string();
        tx.with_connection(move|c|Box::pin(async move {
            let rows=if let Some((outcome,stage,reason))=outcome {sqlx::query("UPDATE mdm_webhook.deliveries SET last_outcome=$3,last_stage=$4,last_reason=$5 WHERE tenant_id=$1::uuid AND id=$2 AND expected_epoch=current_setting('rss.execution_epoch')::bigint").bind(t).bind(id).bind(outcome).bind(stage).bind(reason).execute(c).await?.rows_affected()}
            else{sqlx::query("UPDATE mdm_webhook.deliveries SET attempts=attempts+1,last_outcome='unknown',last_stage=NULL,last_reason=NULL WHERE tenant_id=$1::uuid AND id=$2 AND expected_epoch=current_setting('rss.execution_epoch')::bigint AND attempts<9223372036854775807").bind(t).bind(id).execute(c).await?.rows_affected()};
            if rows==1 {Ok(())}else{Err(sqlx::Error::Protocol("webhook observation binding".into()))}
        })).await
    })).await.fold(Ok,Err,Err,Err,Err,Err)
}
#[expect(
    clippy::too_many_arguments,
    reason = "fenced execution and independently owned transport, time, diagnostics and cancellation ports are explicit"
)]
pub async fn run<H, A, T, W, E>(
    storage: rss_transactional_messaging::fence::StorageIdentity,
    discovery_pool: sqlx::PgPool,
    runtime: Arc<PgRuntime>,
    host: Arc<H>,
    authorizer: A,
    timer: Arc<T>,
    wall: W,
    emitter: Arc<E>,
    token: tokio_util::sync::CancellationToken,
) -> Result<(), MessagingError>
where
    H: Eligibility,
    A: transport::TargetAuthorizer + 'static,
    T: ExecutionTimer + 'static,
    W: transport::WallClock + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    let budget = DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(6),
        Duration::from_secs(6),
        Duration::from_secs(6),
    )
    .expect("constant webhook budgets");
    let source = Arc::new(
        PgOutboxStore::<crate::fanout::Completed>::new(
            runtime.clone(),
            events::domain(events::SOURCE_DOMAIN),
            budget,
        )
        .map_err(|e| rss_transactional_messaging::error::MessagingError::new(e.kind(), e))?,
    );
    let delivery = Arc::new(
        PgOutboxStore::<transport::WebhookPublishReceipt>::new(
            runtime.clone(),
            events::domain(events::DELIVERY_DOMAIN),
            budget,
        )
        .map_err(|e| rss_transactional_messaging::error::MessagingError::new(e.kind(), e))?,
    );
    let fanout = Arc::new(Fanout {
        storage,
        runtime: runtime.clone(),
        host,
    });
    let publisher = Arc::new(Observed {
        storage,
        discovery_pool: discovery_pool.clone(),
        inner: transport::WebhookPublisher::new(
            authorizer,
            Timer(timer.clone()),
            wall,
            transport::Limits::new(4, 64 * 1024, 16, 64, 32768).expect("bounded HTTP resources"),
        ),
        runtime,
        timer: timer.clone(),
    });
    let lanes = RelayLanes {
        storage,
        pool: discovery_pool,
        timer,
        emitter,
        token,
    };
    tokio::join!(
        lanes.drive(events::SOURCE_DOMAIN, source, fanout, 2),
        lanes.drive(events::DELIVERY_DOMAIN, delivery, publisher, 4)
    );
    Ok(())
}

struct RelayLanes<T, E> {
    storage: rss_transactional_messaging::fence::StorageIdentity,
    pool: sqlx::PgPool,
    timer: Arc<T>,
    emitter: Arc<E>,
    token: tokio_util::sync::CancellationToken,
}

impl<T: ExecutionTimer + 'static, E: TransactionalMessagingEmitter + 'static> RelayLanes<T, E> {
    async fn drive<P>(
        &self,
        domain: &'static str,
        store: Arc<PgOutboxStore<P::Receipt>>,
        publisher: Arc<P>,
        capacity: usize,
    ) where
        P: Publisher<Vec<u8>> + 'static,
        P::Receipt: 'static,
    {
        let idle = Duration::from_millis(500);
        let notify = tokio::sync::Notify::new();
        rss_mdm_work_page::run(
            NonZeroUsize::new(capacity).expect("relay capacity"),
            idle,
            &self.token,
            &notify,
            |after: Option<(Uuid, i64)>| async move {
                sqlx::query_as(
                    "SELECT tenant_id,expected_epoch FROM mdm_webhook.work_scopes($1,$2,$3)",
                )
                .bind(domain)
                .bind(after.map(|v| v.0))
                .bind(after.map(|v| v.1))
                .fetch_all(&self.pool)
                .await
                .map_err(|_| ())
            },
            |(tenant, epoch), _| {
                let (store, publisher, timer, emitter) = (
                    store.clone(),
                    publisher.clone(),
                    self.timer.clone(),
                    self.emitter.clone(),
                );
                let storage = self.storage;
                async move {
                    let tenant = rss_request_context::TenantId::parse(&tenant.to_string())
                        .map_err(|_| ())?;
                    let epoch =
                        rss_transactional_messaging::fence::Epoch::new(epoch).map_err(|_| ())?;
                    let binding = rss_transactional_messaging::fence::ExecutionBinding::new(
                        storage, tenant, epoch,
                    );
                    let report = relay_once(
                        binding,
                        store.as_ref(),
                        publisher.as_ref(),
                        timer.as_ref(),
                        emitter.as_ref(),
                        NonZeroUsize::MIN,
                    )
                    .await
                    .map_err(|_| ())?;
                    Ok(if report.published() > 0 {
                        Duration::ZERO
                    } else {
                        idle
                    })
                }
            },
            |_| {},
        )
        .await;
    }
}
pub(crate) async fn delivery_execution(
    pool: &sqlx::PgPool,
    storage: rss_transactional_messaging::fence::StorageIdentity,
    tenant: rss_request_context::TenantId,
    id: Uuid,
) -> Result<rss_transactional_messaging::fence::ExecutionBinding, crate::Error> {
    let epoch: Option<i64> = sqlx::query_scalar("SELECT mdm_webhook.delivery_epoch($1::uuid,$2)")
        .bind(tenant.to_string())
        .bind(id)
        .fetch_one(pool)
        .await?;
    let epoch =
        rss_transactional_messaging::fence::Epoch::new(epoch.ok_or(crate::Error::NotFound)?)
            .map_err(|_| crate::Error::Invalid)?;
    Ok(rss_transactional_messaging::fence::ExecutionBinding::new(
        storage, tenant, epoch,
    ))
}

struct Timer<T>(Arc<T>);
impl<T: ExecutionTimer> rss_request_context::Clock for Timer<T> {
    fn now(&self) -> std::time::Instant {
        self.0.now()
    }
}
impl<T: ExecutionTimer> ExecutionTimer for Timer<T> {
    async fn sleep_until(&self, d: Deadline) {
        self.0.sleep_until(d).await
    }
}
