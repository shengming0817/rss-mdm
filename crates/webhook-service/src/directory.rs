//! Safe metadata catalogs and bounded SQL reads; the application supplies current visibility.
//! ref: sqlx sqlx-core/src/query_builder.rs@v0.9.0
use crate::{Error, model::EventType};
use rss_mdm_query::directory::{Field, Kind, Position, Query, Schema};
use serde_json::Value;
use sqlx::{PgConnection, QueryBuilder};
use uuid::Uuid;
pub static SUBSCRIPTIONS: Schema = Schema {
    id: "webhook_subscriptions",
    keys: &["id"],
    default_limit: 32,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("targetVersion", Kind::Integer),
        Field::scalar("enabled", Kind::Boolean),
        Field::scalar("deleted", Kind::Boolean),
        Field::output("settings"),
    ],
};
pub static DELIVERIES: Schema = Schema {
    id: "webhook_deliveries",
    keys: &["id"],
    default_limit: 32,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("eventId", Kind::Uuid),
        Field::scalar("subscriptionId", Kind::Uuid),
        Field::scalar("targetVersion", Kind::Integer),
        Field::scalar("recoveryVersion", Kind::Integer),
        Field::scalar("attempts", Kind::Integer),
        Field::scalar("status", Kind::Text),
        Field::output("sourceDelivery"),
        Field::output("redriveWindowOpen"),
        Field::output("transportObservation"),
        Field::output("failureStage"),
        Field::output("failureReason"),
    ],
};
pub fn query_error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Invalid,
    }
}
fn column(n: &str) -> &'static str {
    match n {
        "id" => "(row->>'id') COLLATE \"C\"",
        "eventId" => "(row->>'eventId') COLLATE \"C\"",
        "subscriptionId" => "(row->>'subscriptionId') COLLATE \"C\"",
        "revision" => "(row->>'revision')::bigint",
        "targetVersion" => "(row->>'targetVersion')::bigint",
        "recoveryVersion" => "(row->>'recoveryVersion')::bigint",
        "attempts" => "(row->>'attempts')::bigint",
        "enabled" => "(row->>'enabled')::boolean",
        "deleted" => "(row->>'deleted')::boolean",
        "status" => "(row->>'status') COLLATE \"C\"",
        _ => unreachable!("checked webhook field"),
    }
}
pub async fn subscriptions(
    c: &mut PgConnection,
    t: Uuid,
    q: &Query,
    after: Option<&Position>,
) -> Result<Vec<Value>, Error> {
    q.require_schema(&SUBSCRIPTIONS).map_err(query_error)?;
    let mut sql = QueryBuilder::new(
        "SELECT row FROM (SELECT jsonb_build_object('id',id,'revision',revision,'targetVersion',target_version,'enabled',enabled,'deleted',deleted,'settings',settings) row FROM mdm_webhook.subscriptions WHERE tenant_id=",
    );
    sql.push_bind(t).push(") records WHERE true");
    rss_mdm_query_postgres::append(&mut sql, q, after, column).map_err(query_error)?;
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
    rss_mdm_query_postgres::append(&mut sql, q, after, column).map_err(query_error)?;
    Ok(sql.build_query_scalar().fetch_all(c).await?)
}
