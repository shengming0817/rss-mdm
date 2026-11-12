//! Safe metadata catalogs and bounded SQL reads; the application supplies current visibility.
//! ref: sqlx sqlx-core/src/query_builder.rs@v0.9.0
use crate::{Error, model::EventType};
use rss_mdm_query::directory::{Position, Query, Schema};
use serde_json::Value;
use sqlx::{PgConnection, QueryBuilder};
use uuid::Uuid;
pub static SUBSCRIPTIONS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<crate::model::Subscription>("webhook_subscriptions", &["id"], 32, 1000, &[])
        .expect("Webhook subscription model is fully described")
});
static SUBSCRIPTION_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        use rss_mdm_query_postgres::{Bindings, Source};
        Bindings::new(
            &SUBSCRIPTIONS,
            &[
                Source::column("id", "(row->>'id') COLLATE \"C\""),
                Source::column("revision", "(row->>'revision')::bigint"),
                Source::column("targetVersion", "(row->>'targetVersion')::bigint"),
                Source::column("enabled", "(row->>'enabled')::boolean"),
                Source::column("deleted", "(row->>'deleted')::boolean"),
                Source::json("settings", "row->'settings'"),
            ],
        )
        .expect("Webhook storage binds every subscription field")
    });
pub static DELIVERIES: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<crate::management::response::Delivery>(
        "webhook_deliveries",
        &["id"],
        32,
        1000,
        &[],
    )
    .expect("Public directory model")
});
pub fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Invalid,
    }
}
pub async fn subscriptions(
    c: &mut PgConnection,
    t: Uuid,
    q: &Query,
    after: Option<&Position>,
) -> Result<Vec<Value>, Error> {
    q.require_schema(SUBSCRIPTION_BINDINGS.schema())
        .map_err(query_error)?;
    let mut sql = QueryBuilder::new(
        "SELECT row FROM (SELECT jsonb_build_object('id',id,'revision',revision,'targetVersion',target_version,'enabled',enabled,'deleted',deleted,'settings',settings) row FROM mdm_webhook.subscriptions WHERE tenant_id=",
    );
    sql.push_bind(t).push(") records WHERE true");
    rss_mdm_query_postgres::append(&mut sql, q, after, &*SUBSCRIPTION_BINDINGS)
        .map_err(query_error)?;
    Ok(sql.build_query_scalar().fetch_all(c).await?)
}
pub async fn deliveries(
    c: &mut PgConnection,
    t: Uuid,
    q: &Query,
    after: Option<&Position>,
    allowed: &[(EventType, Option<Vec<String>>)],
    only: Option<Uuid>,
) -> Result<Vec<Value>, Error> {
    q.require_schema(&DELIVERIES).map_err(query_error)?;
    let mut sql = QueryBuilder::new(
        "SELECT row FROM (SELECT jsonb_build_object('id',d.id,'eventId',d.event_id,'subscriptionId',d.subscription,'targetVersion',d.target_version,'sourceDelivery',d.source_delivery,'recoveryVersion',o.recovery_version,'redriveWindowOpen',coalesce(o.automatic_retry_deadline>clock_timestamp(),false),'attempts',d.attempts,'status',o.status,'transportObservation',d.last_outcome,'failureStage',d.last_stage,'failureReason',d.last_reason) row FROM mdm_webhook.deliveries d JOIN rss_transactional_messaging.outbox o ON(o.tenant_id,o.message_id)=(d.tenant_id,d.id::text) JOIN mdm_webhook.events e ON(e.tenant_id,e.id)=(d.tenant_id,d.event_id) WHERE o.domain='mdm-webhook-delivery' AND o.fingerprint=d.fingerprint AND d.tenant_id=",
    );
    sql.push_bind(t);
    if let Some(id) = only {
        sql.push(" AND d.id=").push_bind(id);
    }
    sql.push(" AND (false");
    for (kind, devices) in allowed {
        sql.push(" OR (e.document->>'eventType'=").push_bind(
            serde_json::to_value(kind)?
                .as_str()
                .ok_or(Error::Invalid)?
                .to_owned(),
        );
        if let Some(devices) = devices {
            sql.push(" AND e.document->>'deviceId'=ANY(")
                .push_bind(devices.clone())
                .push(")");
        }
        sql.push(")");
    }
    sql.push(")) records WHERE true");
    rss_mdm_query_postgres::append(&mut sql, q, after, &*DELIVERY_BINDINGS).map_err(query_error)?;
    Ok(sql.build_query_scalar().fetch_all(c).await?)
}

/// Captured subscription parameters; decoding stays inside the application's audit boundary.
#[derive(Clone, serde::Serialize)]
#[serde(transparent)]
pub struct SubscriptionInput(String);
impl SubscriptionInput {
    pub fn execution() -> &'static rss_mdm_query::directory::Execution {
        SUBSCRIPTION_BINDINGS.execution()
    }
    pub fn capture(raw: &str) -> Self {
        Self(raw.to_owned())
    }
    pub fn schema() -> &'static Schema {
        SUBSCRIPTION_BINDINGS.schema()
    }
    pub fn parse(&self) -> rss_mdm_query::Result<Query> {
        Self::schema().parse(&self.0)
    }
}
/// Captured delivery parameters use the delivery owner's field catalog.
#[derive(Clone, serde::Serialize)]
#[serde(transparent)]
pub struct DeliveryInput(String);
impl DeliveryInput {
    pub fn execution() -> &'static rss_mdm_query::directory::Execution {
        DELIVERY_BINDINGS.execution()
    }
    pub fn capture(raw: &str) -> Self {
        Self(raw.to_owned())
    }
    pub fn schema() -> &'static Schema {
        &DELIVERIES
    }
    pub fn parse(&self) -> rss_mdm_query::Result<Query> {
        Self::schema().parse(&self.0)
    }
}

pub static DELIVERY_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &DELIVERIES,
            &[
                rss_mdm_query_postgres::Source::json("id", "row#>'{id}'"),
                rss_mdm_query_postgres::Source::json("eventId", "row#>'{eventId}'"),
                rss_mdm_query_postgres::Source::json("subscriptionId", "row#>'{subscriptionId}'"),
                rss_mdm_query_postgres::Source::json("targetVersion", "row#>'{targetVersion}'"),
                rss_mdm_query_postgres::Source::json("sourceDelivery", "row#>'{sourceDelivery}'"),
                rss_mdm_query_postgres::Source::json("recoveryVersion", "row#>'{recoveryVersion}'"),
                rss_mdm_query_postgres::Source::json(
                    "redriveWindowOpen",
                    "row#>'{redriveWindowOpen}'",
                ),
                rss_mdm_query_postgres::Source::json("attempts", "row#>'{attempts}'"),
                rss_mdm_query_postgres::Source::json("status", "row#>'{status}'"),
                rss_mdm_query_postgres::Source::json(
                    "transportObservation",
                    "row#>'{transportObservation}'",
                ),
                rss_mdm_query_postgres::Source::json("failureStage", "row#>'{failureStage}'"),
                rss_mdm_query_postgres::Source::json("failureReason", "row#>'{failureReason}'"),
            ],
        )
        .expect("Complete public model storage binding")
    });
