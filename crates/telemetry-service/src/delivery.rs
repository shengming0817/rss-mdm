//! The sole pending-content carrier is the existing RSS Outbox.
use crate::{Error, admission::Accepted};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;
use rss_transactional_messaging::{message::*, outbox::PendingMessage};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
pub(crate) const DOMAIN: &str = "mdm-telemetry";
const ROUTE: &str = "mdm.telemetry.accepted.v1";
static SCHEMA: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    serde_json::to_vec(&schemars::schema_for!(Accepted)).expect("typed accepted-message schema")
});
pub(crate) async fn append_on(c: &mut PgConnection, accepted: &Accepted) -> Result<(), Error> {
    let tenant = TenantId::parse(&accepted.tenant).map_err(|_| Error::Invalid)?;
    let metadata = MessageMetadata::new(
        AuthoredMessageMetadata::new(
            tenant,
            Timepoint::try_from(accepted.received_at / 1_000_000).map_err(|_| Error::Invalid)?,
            MessagingDomain::parse(DOMAIN).map_err(|_| Error::Invalid)?,
            MessageRoute::parse(ROUTE).map_err(|_| Error::Invalid)?,
            ContractIdentity::new(
                ContractId::parse("mdm.telemetry.accepted").map_err(|_| Error::Invalid)?,
                ContractVersion::from_static_major(1),
                SchemaDigest::parse(&format!("sha256:{:x}", Sha256::digest(SCHEMA.as_slice())))
                    .map_err(|_| Error::Invalid)?,
            ),
        ),
        MessageMetadataExtensions::new(None, None, None, Default::default()),
    );
    let pending = PendingMessage::new(MessageEnvelope::new(
        MessageId::parse(&accepted.input.batch_id.to_string()).map_err(|_| Error::Invalid)?,
        metadata,
        serde_json::to_vec(accepted)?,
    ));
    let envelope = pending.envelope();
    let result: String = sqlx::query_scalar("SELECT rss_transactional_messaging.append_outbox($1,$2)")
        .bind(envelope.canonical_bytes()).bind(serde_json::json!({"trace":envelope.transport_context().trace(),"tenant_authority":envelope.transport_context().tenant_authority()})).fetch_one(c).await?;
    match result.as_str() {
        "inserted" | "already_present" => Ok(()),
        "conflict" => Err(Error::Conflict),
        _ => Err(Error::Storage),
    }
}

use crate::{Service, backend::SystemClock};
use rss_request_context::{Deadline, ExecutionTimer};
use rss_timeseries::{Access, Authority, Authorized, Batch, Outcome};
use rss_transactional_messaging::{
    policy::{DeliveryBudget, OperationDeadline},
    transport::*,
};
use rss_transactional_messaging_postgres::PgOutboxStore;
use rss_transactional_messaging_runtime::relay::{RelayConfig, RelayWorker};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
struct BatchAuthority<'a>(&'a Batch);
impl Authority for BatchAuthority<'_> {
    fn authorize(&self, access: Access<'_>) -> Result<(), rss_timeseries::Error> {
        match access {
            Access::Write(batch) if batch.digest()? == self.0.digest()? => Ok(()),
            _ => Err(rss_timeseries::Error::InvalidInput),
        }
    }
}
/// Private confirmation can be issued only after all required destination admissions.
pub struct Published(());
struct PublisherService(Arc<Service>);
fn failure(
    kind: PublishFailureKind,
    stage: PublishFailureStage,
    reason: PublishFailureReason,
) -> PublishFailure {
    PublishFailure::new(kind, stage, reason)
}
impl Publisher<Vec<u8>> for PublisherService {
    type Receipt = Published;
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        budget: OperationDeadline,
    ) -> PublishOutcome<Published> {
        let uncertain = || {
            PublishOutcome::Ambiguous(failure(
                PublishFailureKind::Transient,
                PublishFailureStage::Confirm,
                PublishFailureReason::TransportUnavailable,
            ))
        };
        let Ok(input) = serde_json::from_slice::<Accepted>(message.payload()) else {
            return PublishOutcome::DefinitelyNotPublished(failure(
                PublishFailureKind::Permanent,
                PublishFailureStage::Encode,
                PublishFailureReason::InvalidMessage,
            ));
        };
        if input.tenant != self.0.tenant.to_string()
            || message.metadata().tenant_id() != self.0.tenant
            || input.input.batch_id.to_string() != message.id().as_str()
        {
            return uncertain();
        }
        match self.0.accepted_context(&input).await {
            Ok(true) => return PublishOutcome::Confirmed(Published(())),
            Ok(false) => {}
            Err(_) => return uncertain(),
        }
        let Ok(cutoff) = Deadline::from_timeout(&SystemClock, budget.timeout()) else {
            return uncertain();
        };
        let Ok(history) = input.history() else {
            return uncertain();
        };
        if history.is_some() {
            for field in &input.profile.spec().fields {
                match self.0.synchronize(field.clone(), cutoff).await {
                    Ok(true) => {}
                    _ => return uncertain(),
                }
            }
        }
        let service = self.0.clone();
        let batch_id = input.input.batch_id;
        let failure = Arc::new(std::sync::Mutex::new(None));
        let rejected = failure.clone();
        let outcome = self
            .0
            .runtime
            .local_tx(self.0.tenant, budget, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            deliver_on(&service, c, &input, history, cutoff)
                                .await
                                .map_err(|error| {
                                    *rejected.lock().expect("delivery rejection") = Some(error);
                                    sqlx::Error::Protocol(
                                        "telemetry destination not confirmed".into(),
                                    )
                                })
                        })
                    })
                    .await
                })
            })
            .await;
        let confirmed = outcome.fold(
            |_| true,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| false,
        );
        if confirmed {
            return PublishOutcome::Confirmed(Published(()));
        }
        let state = match *failure.lock().expect("delivery rejection") {
            Some(Error::Denied | Error::Conflict | Error::Invalid) => "blocked",
            _ => "unknown",
        };
        // A derived observation, not a second delivery state machine: RSS still owns retry.
        let tenant = self.0.tenant;
        let _=self.0.runtime.local_tx(tenant,crate::deadline(),move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("UPDATE mdm_telemetry.batches SET delivery=$3 WHERE tenant_id=$1::uuid AND id=$2 AND delivery<>'published'")
                    .bind(tenant.to_string()).bind(batch_id).bind(state).execute(c).await?;
                Ok(())
            })).await
        })).await;
        uncertain()
    }
}
async fn deliver_on(
    service: &Service,
    c: &mut PgConnection,
    input: &Accepted,
    history: Option<Batch>,
    cutoff: Deadline,
) -> Result<(), Error> {
    use sqlx::Row;
    let row = sqlx::query("SELECT input_digest,context_digest,delivery,registration,credential,epoch FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE")
        .bind(service.tenant.to_string()).bind(input.input.batch_id).fetch_one(&mut *c).await?;
    if row.try_get::<Vec<u8>, _>("context_digest")?
        != Sha256::digest(serde_json::to_vec(input)?).to_vec()
        || row.try_get::<Vec<u8>, _>("input_digest")?
            != Sha256::digest(serde_json::to_vec(&input.input)?).to_vec()
        || row.try_get::<uuid::Uuid, _>("registration")? != input.registration
        || row.try_get::<uuid::Uuid, _>("credential")? != input.credential
        || row.try_get::<uuid::Uuid, _>("epoch")? != input.epoch
    {
        return Err(Error::Conflict);
    }
    if row.try_get::<String, _>("delivery")? == "published" {
        return Ok(());
    }
    if let Some(batch) = history {
        let authorized = Authorized::<Batch>::verify(&BatchAuthority(&batch), batch.clone())?;
        match service.backend.write(&authorized, cutoff).await? {
            Outcome::Accepted(_) | Outcome::Replay(_) => {}
            Outcome::Unknown => return Err(Error::Unknown),
        }
    }
    if input.profile.spec().projection != rss_mdm_resource::TelemetryProjection::History {
        crate::current::deliver_on(c, service.tenant, input).await?;
    }
    sqlx::query(
        "UPDATE mdm_telemetry.batches SET delivery='published' WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(service.tenant.to_string())
    .bind(input.input.batch_id)
    .execute(c)
    .await?;
    Ok(())
}
impl ExecutionTimer for SystemClock {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::time::sleep_until(deadline.instant().into()).await;
    }
}
struct Diagnostics;
impl rss_transactional_messaging::observability::TransactionalMessagingEmitter for Diagnostics {
    fn emit(
        &self,
        event: rss_transactional_messaging::observability::TransactionalMessagingObservation,
    ) {
        if let rss_transactional_messaging::observability::TransactionalMessagingObservation::RuntimeFailure { phase,kind } = event {
            eprintln!("{}",serde_json::json!({"event":"telemetry_delivery_failure","phase":phase.as_label(),"kind":kind.as_label()}));
        }
    }
}
impl Service {
    /// Use the existing RSS relay, its ownership fences, retry deadlines and dead-letter state.
    pub async fn run(
        self: Arc<Self>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), Error> {
        struct Running(Arc<Service>);
        impl Drop for Running {
            fn drop(&mut self) {
                self.0
                    .running
                    .store(false, std::sync::atomic::Ordering::Release);
            }
        }
        self.running
            .store(true, std::sync::atomic::Ordering::Release);
        let _running = Running(self.clone());
        let budget = DeliveryBudget::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .map_err(|_| Error::Invalid)?;
        let store = Arc::new(
            PgOutboxStore::<Published>::new(
                self.runtime.clone(),
                MessagingDomain::parse(DOMAIN).map_err(|_| Error::Invalid)?,
                budget,
            )
            .map_err(|_| Error::Storage)?,
        );
        let worker = RelayWorker::new(
            store,
            Arc::new(PublisherService(self.clone())),
            Arc::new(SystemClock),
            Arc::new(Diagnostics),
            RelayConfig::new(
                Duration::from_millis(500),
                NonZeroUsize::new(2).expect("positive concurrency"),
            )
            .map_err(|_| Error::Invalid)?,
        );
        let local = cancel.child_token();
        let relay_cancel = local.clone();
        let maintenance_cancel = local.clone();
        let (relay, maintenance) = tokio::join!(
            async {
                let result = worker.run(relay_cancel).await.map_err(|_| Error::Storage);
                local.cancel();
                result
            },
            async {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {biased;()=maintenance_cancel.cancelled()=>break, _=interval.tick()=>{}}
                    if self.retain().await.is_err() {
                        eprintln!("telemetry retention maintenance unconfirmed");
                    }
                    if self.retire_definitions().await.is_err() {
                        eprintln!("telemetry definition maintenance unconfirmed");
                    }
                }
                Ok::<(), Error>(())
            }
        );
        relay.and(maintenance)
    }
}

impl Service {
    /// The sealed registration admission is a durable fact. Policy changes and credential
    /// rotation stop new input; they do not rewrite or strand previously accepted samples.
    async fn accepted_context(self: &Arc<Self>, input: &Accepted) -> Result<bool, Error> {
        let tenant = self.tenant;
        let id = input.input.batch_id;
        let context = Sha256::digest(serde_json::to_vec(input)?).to_vec();
        self.runtime.local_tx(tenant,crate::deadline(),move|tx|Box::pin(async move {
            tx.with_connection(move|c|Box::pin(async move {
                use sqlx::Row;
                let row=sqlx::query("SELECT context_digest,delivery FROM mdm_telemetry.batches WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(tenant.to_string()).bind(id).fetch_one(c).await?;
                if row.try_get::<Vec<u8>,_>("context_digest")?!=context {return Err(sqlx::Error::Protocol("sealed telemetry context mismatch".into()));}
                Ok(row.try_get::<String,_>("delivery")?=="published")
            })).await
        })).await.fold(Ok,|_|Err(Error::Storage),|_|Err(Error::Storage),|_|Err(Error::Unknown),|_|Err(Error::Unknown),|_|Err(Error::Storage))
    }
}
