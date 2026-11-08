//! Registration facts enter the public RSS SQL Outbox in this original transaction.
use rss_mdm_webhook_service::{events, model::*};
use sqlx::PgConnection;
use uuid::Uuid;
/// Optional product notification sink, borrowed inside the original registration transaction.
pub trait EventSink: Send + Sync {
    fn emit<'a>(
        &'a self,
        c: &'a mut PgConnection,
        event: &'a Event,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), crate::Error>> + Send + 'a>>;
}
/// MDM's real Webhook adapter; independent hosts explicitly omit this capability.
pub struct WebhookEvents;
impl EventSink for WebhookEvents {
    fn emit<'a>(
        &'a self,
        c: &'a mut PgConnection,
        event: &'a Event,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), crate::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            events::emit_on(c, event).await.map_err(|e| match e {
                rss_mdm_webhook_service::Error::Conflict => crate::Error::Conflict,
                _ => crate::Error::Storage,
            })
        })
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "original transaction notification carries the explicit sink and registration fact coordinates"
)]
pub(crate) async fn device(
    sink: Option<&dyn EventSink>,
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
    channel: &str,
    state: &str,
) -> Result<(), crate::Error> {
    let Some(sink) = sink else {
        return Ok(());
    };
    let kind = if state == "active" {
        EventType::Registered
    } else {
        EventType::Retired
    };
    let event = Event {
        event_id: events::identity(
            Uuid::parse_str(tenant).map_err(|_| crate::Error::Malformed)?,
            &format!("device:{device}:{state}"),
        ),
        event_type: kind,
        version: 1,
        occurred_at: events::now_on(c).await.map_err(|_| crate::Error::Storage)?,
        tenant_id: Uuid::parse_str(tenant).map_err(|_| crate::Error::Malformed)?,
        device_id: device.into(),
        data: EventData::Registration {
            device_id: device.into(),
            channel: channel.into(),
            state: state.into(),
        },
    };
    sink.emit(c, &event).await
}
