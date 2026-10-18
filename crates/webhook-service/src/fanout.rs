//! Durable business progress driven by the same RSS relay as HTTP deliveries.
use crate::{Error, PAGE, PgError, PgRuntime, events, model::*, storage, transport};
use futures::future::BoxFuture;
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    message::MessageEnvelope, policy::OperationDeadline, transport::*,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use std::sync::Arc;
use uuid::Uuid;

pub type ChangePage = (Vec<Event>, Option<String>);

/// The host maps event selection and published compliance changes without a reverse dependency.
pub trait Eligibility: Send + Sync + 'static {
    fn eligible<'a>(
        &'a self,
        c: &'a mut PgConnection,
        subscription: &'a Subscription,
        event: &'a Event,
    ) -> BoxFuture<'a, Result<bool, Error>>;
    fn compliance_page<'a>(
        &'a self,
        c: &'a mut PgConnection,
        source: &'a events::CompliancePublication,
        after: Option<String>,
    ) -> BoxFuture<'a, Result<ChangePage, Error>>;
}
#[derive(Serialize, Deserialize)]
struct Candidate {
    id: Uuid,
    version: i64,
}
pub struct Completed(());
pub struct Fanout<H> {
    pub runtime: Arc<PgRuntime>,
    pub host: Arc<H>,
}
impl<H: Eligibility> Publisher<Vec<u8>> for Fanout<H> {
    type Receipt = Completed;
    async fn publish(
        &self,
        message: &MessageEnvelope<Vec<u8>>,
        deadline: OperationDeadline,
    ) -> PublishOutcome<Completed> {
        let failure = || {
            PublishOutcome::Ambiguous(PublishFailure::new(
                PublishFailureKind::Transient,
                PublishFailureStage::Confirm,
                PublishFailureReason::TransportUnavailable,
            ))
        };
        let Ok(source) = serde_json::from_slice::<events::Source>(message.payload()) else {
            return PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
                PublishFailureKind::Permanent,
                PublishFailureStage::Encode,
                PublishFailureReason::InvalidMessage,
            ));
        };
        let (id, t, valid) = match &source {
            events::Source::Event(e) => (e.event_id, e.tenant_id, e.validate().is_ok()),
            events::Source::Compliance(s) => (
                s.id,
                s.tenant,
                !s.id.is_nil() && !s.run.is_nil() && !s.rule.is_nil() && s.rule_version > 0,
            ),
        };
        if !valid
            || message.id().as_str() != id.to_string()
            || message.metadata().tenant_id().to_string() != t.to_string()
        {
            return PublishOutcome::DefinitelyNotPublished(PublishFailure::new(
                PublishFailureKind::Permanent,
                PublishFailureStage::Encode,
                PublishFailureReason::InvalidMessage,
            ));
        }
        let Ok(tenant) = TenantId::parse(&t.to_string()) else {
            return failure();
        };
        let host = self.host.clone();
        // One page per relay attempt. Partial durable progress is never an acceptance receipt.
        self.runtime
            .local_tx(tenant, deadline, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(match source {
                                events::Source::Event(event) => {
                                    step(c, host.as_ref(), &event).await
                                }
                                events::Source::Compliance(source) => {
                                    compliance_step(c, host.as_ref(), &source).await
                                }
                            })
                        })
                    })
                    .await?
                    .map_err(PgError::from)
                })
            })
            .await
            .fold(
                |complete| {
                    if complete {
                        PublishOutcome::Confirmed(Completed(()))
                    } else {
                        failure()
                    }
                },
                |_| failure(),
                |_| failure(),
                |_| failure(),
                |_| failure(),
                |_| failure(),
            )
    }
}
async fn compliance_step<H: Eligibility>(
    c: &mut PgConnection,
    host: &H,
    source: &events::CompliancePublication,
) -> Result<bool, Error> {
    let row=sqlx::query("SELECT document,cursor,complete FROM mdm_webhook.compliance_sources WHERE tenant_id=$1 AND id=$2 FOR UPDATE").bind(source.tenant).bind(source.id).fetch_one(&mut *c).await?;
    if row.try_get::<serde_json::Value, _>("document")? != serde_json::to_value(source)? {
        return Err(Error::Conflict);
    }
    if row.try_get::<bool, _>("complete")? {
        return Ok(true);
    }
    let (events, next) = host
        .compliance_page(c, source, row.try_get("cursor")?)
        .await?;
    if events.len() > PAGE as usize {
        return Err(Error::Storage);
    }
    for event in events {
        events::emit_derived_on(c, &event, Some(source.id)).await?;
    }
    let complete = next.is_none();
    sqlx::query("UPDATE mdm_webhook.compliance_sources SET cursor=$3,complete=$4 WHERE tenant_id=$1 AND id=$2").bind(source.tenant).bind(source.id).bind(next).bind(complete).execute(c).await?;
    Ok(complete)
}
async fn step<H: Eligibility>(
    c: &mut PgConnection,
    host: &H,
    event: &Event,
) -> Result<bool, Error> {
    let t = event.tenant_id;
    let id = event.event_id;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2798))")
        .bind(format!("{t}:{id}"))
        .execute(&mut *c)
        .await?;
    // Verify the source's exact durable bytes before inspecting subscriptions.
    let body: Vec<u8> =
        sqlx::query_scalar("SELECT body FROM mdm_webhook.events WHERE tenant_id=$1 AND id=$2")
            .bind(t)
            .bind(id)
            .fetch_one(&mut *c)
            .await?;
    if body != serde_json::to_vec(event)? {
        return Err(Error::Conflict);
    }
    let row=sqlx::query("SELECT snapshot,cursor,complete FROM mdm_webhook.fanout WHERE tenant_id=$1 AND id=$2 FOR UPDATE").bind(t).bind(id).fetch_optional(&mut *c).await?;
    let (snapshot, cursor) = if let Some(row) = row {
        if row.try_get::<bool, _>("complete")? {
            return Ok(true);
        }
        (
            serde_json::from_value::<Vec<Candidate>>(row.try_get("snapshot")?)?,
            row.try_get::<i32, _>("cursor")? as usize,
        )
    } else {
        let rows=sqlx::query("SELECT s.* FROM mdm_webhook.subscriptions s JOIN mdm_webhook.versions v ON(v.tenant_id,v.subscription,v.version)=(s.tenant_id,s.id,s.target_version) JOIN mdm_webhook.events e ON e.tenant_id=s.tenant_id AND e.id=$2 WHERE s.tenant_id=$1 AND s.enabled AND NOT s.deleted AND NOT v.retired AND v.activated_at<=e.created_at ORDER BY s.id LIMIT $3")
            .bind(t).bind(event.event_id).bind(crate::MAX_SUBSCRIPTIONS+1).fetch_all(&mut *c).await?;
        if rows.len() > crate::MAX_SUBSCRIPTIONS as usize {
            return Err(Error::Conflict);
        }
        let mut snapshot = Vec::new();
        for row in rows {
            let subscription = storage::decode(row)?;
            if subscription
                .settings
                .event_types
                .contains(&event.event_type)
                && host.eligible(c, &subscription, event).await?
            {
                snapshot.push(Candidate {
                    id: subscription.id,
                    version: subscription.target_version,
                });
            }
        }
        sqlx::query("INSERT INTO mdm_webhook.fanout(tenant_id,id,snapshot) VALUES($1,$2,$3)")
            .bind(t)
            .bind(id)
            .bind(serde_json::to_value(&snapshot)?)
            .execute(&mut *c)
            .await?;
        (snapshot, 0)
    };
    if cursor > snapshot.len() {
        return Err(Error::Storage);
    }
    let end = (cursor + PAGE as usize).min(snapshot.len());
    for candidate in &snapshot[cursor..end] {
        let subscription = storage::get(c, t, candidate.id).await?;
        // A retired version is skipped; it can never be silently rebound to its replacement.
        if subscription.enabled
            && !subscription.deleted
            && subscription.target_version == candidate.version
        {
            queue(c, event, &subscription, None, None).await?;
        }
    }
    let complete = end == snapshot.len();
    sqlx::query("UPDATE mdm_webhook.fanout SET cursor=$3,complete=$4 WHERE tenant_id=$1 AND id=$2")
        .bind(t)
        .bind(id)
        .bind(end as i32)
        .bind(complete)
        .execute(c)
        .await?;
    Ok(complete)
}
pub async fn queue(
    c: &mut PgConnection,
    event: &Event,
    subscription: &Subscription,
    operation: Option<Uuid>,
    source: Option<Uuid>,
) -> Result<Uuid, Error> {
    let version = subscription.target_version;
    let id = events::identity(
        event.event_id,
        &format!(
            "{}:{version}:{}",
            subscription.id,
            operation.map_or_else(|| "automatic".into(), |id| id.to_string())
        ),
    );
    let body: Vec<u8> =
        sqlx::query_scalar("SELECT body FROM mdm_webhook.events WHERE tenant_id=$1 AND id=$2")
            .bind(event.tenant_id)
            .bind(event.event_id)
            .fetch_one(&mut *c)
            .await?;
    let pending = events::message(
        id,
        event.tenant_id,
        event.occurred_at,
        events::DELIVERY_DOMAIN,
        body,
    )?;
    let target = transport::Target::new(
        transport::TargetId::parse(&subscription.id.to_string()).map_err(|_| Error::Invalid)?,
        transport::TargetVersion::new(version.try_into().map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Invalid)?,
    );
    let pending = transport::pending_message(
        pending.envelope().id().clone(),
        pending.envelope().metadata().clone(),
        target,
        pending.envelope().payload().clone(),
    )
    .map_err(|_| Error::Invalid)?;
    let fingerprint = pending.fingerprint().as_bytes().to_vec();
    events::append_on(c, pending).await?;
    sqlx::query("INSERT INTO mdm_webhook.deliveries(tenant_id,id,event_id,subscription,target_version,fingerprint,source_delivery,operation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,id) DO NOTHING")
        .bind(event.tenant_id).bind(id).bind(event.event_id).bind(subscription.id).bind(version).bind(fingerprint).bind(source).bind(operation).execute(c).await?;
    Ok(id)
}
pub async fn replay(
    c: &mut PgConnection,
    t: Uuid,
    source: Uuid,
    operation: Uuid,
) -> Result<serde_json::Value, Error> {
    let request = ("replay", source, operation);
    if let Some(response) = storage::replay_operation(c, t, operation, &request).await? {
        return Ok(response);
    }
    let binding = storage::binding(c, t, source).await?;
    let state:String=sqlx::query_scalar("SELECT status FROM rss_transactional_messaging.outbox WHERE tenant_id=$1 AND message_id=$2 FOR UPDATE").bind(t).bind(source.to_string()).fetch_one(&mut *c).await?;
    if state != "dead_letter" {
        return Err(Error::Conflict);
    }
    let id = queue(
        c,
        &binding.event,
        &binding.subscription,
        Some(operation),
        Some(source),
    )
    .await?;
    let response =
        serde_json::json!({"id":id,"eventId":binding.event.event_id,"sourceDelivery":source});
    storage::record_operation(c, t, operation, &request, &response).await?;
    Ok(response)
}
