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
    A: transport::TargetAuthorizer,
    T: ExecutionTimer + 'static,
    W: transport::WallClock,
    E: TransactionalMessagingEmitter,
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
    let capacity = NonZeroUsize::new(4).expect("positive relay capacity");
    let mut after = None;
    loop {
        if token.is_cancelled() {
            return Ok(());
        }
        let scopes = sqlx::query_as::<_, (Uuid, i64)>(
            "SELECT tenant_id,expected_epoch FROM mdm_webhook.work_scopes($1,$2)",
        )
        .bind(after.map(|v: (Uuid, i64)| v.0))
        .bind(after.map(|v| v.1))
        .fetch_all(&discovery_pool)
        .await;
        let scopes = match scopes {
            Ok(scopes) => scopes,
            Err(_) => {
                tokio::select! {()=token.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_secs(5))=>()}
                continue;
            }
        };
        if scopes.is_empty() {
            after = None;
            tokio::select! {()=token.cancelled()=>return Ok(()),()=tokio::time::sleep(Duration::from_millis(500))=>()}
            continue;
        }
        for (tenant, epoch) in scopes {
            if token.is_cancelled() {
                return Ok(());
            }
            after = Some((tenant, epoch));
            let (Ok(tenant), Ok(epoch)) = (
                rss_request_context::TenantId::parse(&tenant.to_string()),
                rss_transactional_messaging::fence::Epoch::new(epoch),
            ) else {
                continue;
            };
            let binding =
                rss_transactional_messaging::fence::ExecutionBinding::new(storage, tenant, epoch);
            let _ = relay_once(
                binding,
                source.as_ref(),
                fanout.as_ref(),
                timer.as_ref(),
                emitter.as_ref(),
                capacity,
            )
            .await;
            if token.is_cancelled() {
                return Ok(());
            }
            let _ = relay_once(
                binding,
                delivery.as_ref(),
                publisher.as_ref(),
                timer.as_ref(),
                emitter.as_ref(),
                capacity,
            )
            .await;
        }
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
