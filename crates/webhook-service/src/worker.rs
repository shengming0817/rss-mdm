use crate::{
    PgError, PgRuntime, events,
    fanout::{Eligibility, Fanout},
    transport,
};
use rss_request_context::{Deadline, ExecutionTimer, TenantId};
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
use rss_transactional_messaging_runtime::relay::{RelayConfig, RelayWorker};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use uuid::Uuid;
struct Observed<P, T> {
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
        if within(self.timer.as_ref(), cutoff, |d| {
            record(&self.runtime, tenant, id, None, d)
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
            record(&self.runtime, tenant, id, Some(observation), d)
        })
        .await;
        result
    }
}
async fn record(
    runtime: &PgRuntime,
    tenant: TenantId,
    id: Uuid,
    outcome: Option<(&'static str, Option<&'static str>, Option<&'static str>)>,
    deadline: OperationDeadline,
) -> Result<(), PgError> {
    runtime.local_tx(tenant,deadline,move|tx|Box::pin(async move {
        let t=tenant.to_string();
        tx.with_connection(move|c|Box::pin(async move {
            let rows=if let Some((outcome,stage,reason))=outcome {sqlx::query("UPDATE mdm_webhook.deliveries SET last_outcome=$3,last_stage=$4,last_reason=$5 WHERE tenant_id=$1::uuid AND id=$2").bind(t).bind(id).bind(outcome).bind(stage).bind(reason).execute(c).await?.rows_affected()}
            else{sqlx::query("UPDATE mdm_webhook.deliveries SET attempts=attempts+1,last_outcome='unknown',last_stage=NULL,last_reason=NULL WHERE tenant_id=$1::uuid AND id=$2 AND attempts<9223372036854775807").bind(t).bind(id).execute(c).await?.rows_affected()};
            if rows==1 {Ok(())}else{Err(sqlx::Error::Protocol("webhook observation binding".into()))}
        })).await
    })).await.fold(Ok,Err,Err,Err,Err,Err)
}
pub async fn run<H, A, T, W, E>(
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
    let config = RelayConfig::new(
        Duration::from_millis(500),
        NonZeroUsize::new(4).expect("positive relay capacity"),
    )
    .expect("bounded relay interval");
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
        runtime: runtime.clone(),
        host,
    });
    let publisher = Arc::new(Observed {
        inner: transport::WebhookPublisher::new(
            authorizer,
            Timer(timer.clone()),
            wall,
            transport::Limits::new(4, 64 * 1024, 16, 64, 32768).expect("bounded HTTP resources"),
        ),
        runtime,
        timer: timer.clone(),
    });
    let source = RelayWorker::new(source, fanout, timer.clone(), emitter.clone(), config);
    let delivery = RelayWorker::new(delivery, publisher, timer, emitter, config);
    tokio::try_join!(source.run(token.clone()), delivery.run(token))?;
    Ok(())
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
