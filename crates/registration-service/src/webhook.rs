//! Registration facts enter the public RSS SQL Outbox in this original transaction.
use rss_mdm_webhook_service::{events, model::*};
use sqlx::PgConnection;
use uuid::Uuid;
pub(crate) async fn registration(
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
    id: Uuid,
    generation: i64,
    channel: &str,
    state: &str,
) -> Result<(), crate::Error> {
    let kind = if state == "active" {
        EventType::Registered
    } else {
        EventType::Retired
    };
    let event = Event {
        event_id: events::identity(id, &format!("registration:{generation}:{state}")),
        event_type: kind,
        version: 1,
        occurred_at: events::now_on(c).await.map_err(|_| crate::Error::Storage)?,
        tenant_id: Uuid::parse_str(tenant).map_err(|_| crate::Error::Malformed)?,
        device_id: device.into(),
        data: EventData::Registration {
            registration_id: id,
            generation,
            channel: channel.into(),
            state: state.into(),
        },
    };
    events::emit_on(c, &event).await.map_err(|e| match e {
        rss_mdm_webhook_service::Error::Conflict => crate::Error::Conflict,
        _ => crate::Error::Storage,
    })
}
