use crate::{Error, MAX_SUBSCRIPTIONS, model::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Change {
    Put(Settings),
    Enabled(bool),
    Delete,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mutation {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub change: Change,
}

pub(crate) fn decode(row: sqlx::postgres::PgRow) -> Result<Subscription, Error> {
    Ok(Subscription {
        id: row.try_get("id")?,
        revision: row.try_get("revision")?,
        target_version: row.try_get("target_version")?,
        enabled: row.try_get("enabled")?,
        deleted: row.try_get("deleted")?,
        settings: serde_json::from_value(row.try_get("settings")?)?,
    })
}
pub async fn get(c: &mut PgConnection, t: Uuid, id: Uuid) -> Result<Subscription, Error> {
    decode(
        sqlx::query("SELECT * FROM mdm_webhook.subscriptions WHERE tenant_id=$1 AND id=$2")
            .bind(t)
            .bind(id)
            .fetch_optional(c)
            .await?
            .ok_or(Error::NotFound)?,
    )
}
pub async fn replay_operation(
    c: &mut PgConnection,
    t: Uuid,
    op: Uuid,
    request: &impl Serialize,
) -> Result<Option<Value>, Error> {
    if op.is_nil() {
        return Err(Error::Invalid);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2796))")
        .bind(format!("{t}:{op}"))
        .execute(&mut *c)
        .await?;
    let row = sqlx::query(
        "SELECT fingerprint,response FROM mdm_webhook.operations WHERE tenant_id=$1 AND id=$2",
    )
    .bind(t)
    .bind(op)
    .fetch_optional(c)
    .await?;
    row.map(|row| {
        let old: Vec<u8> = row.try_get("fingerprint")?;
        if old.as_slice() != Sha256::digest(serde_json::to_vec(request)?).as_slice() {
            return Err(Error::Conflict);
        }
        Ok(row.try_get("response")?)
    })
    .transpose()
}
pub async fn record_operation(
    c: &mut PgConnection,
    t: Uuid,
    op: Uuid,
    request: &impl Serialize,
    response: &Value,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO mdm_webhook.operations(tenant_id,id,fingerprint,response) VALUES($1,$2,$3,$4)",
    )
    .bind(t)
    .bind(op)
    .bind(Sha256::digest(serde_json::to_vec(request)?).to_vec())
    .bind(response)
    .execute(c)
    .await?;
    Ok(())
}
/// The host authorizes management; persisted subscriptions belong to the tenant.
pub async fn mutate(
    c: &mut PgConnection,
    t: Uuid,
    id: Uuid,
    request: &Mutation,
) -> Result<Value, Error> {
    if id.is_nil() || request.expected_revision < 0 {
        return Err(Error::Invalid);
    }
    let input = (id, request);
    if let Some(value) = replay_operation(c, t, request.operation_id, &input).await? {
        return Ok(value);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2797))")
        .bind(t.to_string())
        .execute(&mut *c)
        .await?;
    let old = match get(c, t, id).await {
        Ok(v) => Some(v),
        Err(Error::NotFound) => None,
        Err(e) => return Err(e),
    };
    if old.as_ref().map_or(0, |s| s.revision) != request.expected_revision
        || old.as_ref().is_some_and(|s| s.deleted)
    {
        return Err(Error::Conflict);
    }
    let revision = request
        .expected_revision
        .checked_add(1)
        .ok_or(Error::Conflict)?;
    let mut settings = match (&request.change, &old) {
        (Change::Put(s), _) => s.clone(),
        (_, Some(s)) => s.settings.clone(),
        _ => return Err(Error::Invalid),
    };
    settings.event_types.sort();
    settings.validate()?;
    if old.is_none() {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mdm_webhook.subscriptions WHERE tenant_id=$1 AND NOT deleted",
        )
        .bind(t)
        .fetch_one(&mut *c)
        .await?;
        if count >= MAX_SUBSCRIPTIONS {
            return Err(Error::Conflict);
        }
    }
    let enabled = match &request.change {
        Change::Enabled(v) => *v,
        Change::Delete => false,
        _ => old.as_ref().is_some_and(|s| s.enabled),
    };
    let deleted = matches!(request.change, Change::Delete);
    let rotate = old
        .as_ref()
        .is_none_or(|s| !s.settings.same_delivery(&settings) || s.enabled != enabled || deleted);
    let version = match &old {
        None => 1,
        Some(s) if rotate => s.target_version.checked_add(1).ok_or(Error::Conflict)?,
        Some(s) => s.target_version,
    };
    if rotate && old.is_some() {
        sqlx::query("UPDATE mdm_webhook.versions SET retired=true WHERE tenant_id=$1 AND subscription=$2 AND version=$3").bind(t).bind(id).bind(old.as_ref().ok_or(Error::Conflict)?.target_version).execute(&mut *c).await?;
    }
    sqlx::query("INSERT INTO mdm_webhook.subscriptions VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,target_version=excluded.target_version,enabled=excluded.enabled,deleted=excluded.deleted,settings=excluded.settings")
        .bind(t).bind(id).bind(revision).bind(version).bind(enabled).bind(deleted).bind(serde_json::to_value(&settings)?).execute(&mut *c).await?;
    if rotate {
        sqlx::query("INSERT INTO mdm_webhook.versions(tenant_id,subscription,version,settings,activated_at) VALUES($1,$2,$3,$4,CASE WHEN $5 THEN clock_timestamp() ELSE NULL END)").bind(t).bind(id).bind(version).bind(serde_json::to_value(&settings)?).bind(enabled).execute(&mut *c).await?;
    }
    let result = serde_json::to_value(get(c, t, id).await?)?;
    record_operation(c, t, request.operation_id, &input, &result).await?;
    Ok(result)
}
pub async fn event(c: &mut PgConnection, t: Uuid, id: Uuid) -> Result<Event, Error> {
    let raw: Value =
        sqlx::query_scalar("SELECT document FROM mdm_webhook.events WHERE tenant_id=$1 AND id=$2")
            .bind(t)
            .bind(id)
            .fetch_optional(c)
            .await?
            .ok_or(Error::NotFound)?;
    let event: Event = serde_json::from_value(raw)?;
    event.validate()?;
    Ok(event)
}
/// Immutable delivery facts remain readable after a target is stopped or replaced.
pub async fn delivery_event(c: &mut PgConnection, t: Uuid, id: Uuid) -> Result<Event, Error> {
    let event_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT event_id FROM mdm_webhook.deliveries WHERE tenant_id=$1 AND id=$2",
    )
    .bind(t)
    .bind(id)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Error::NotFound)?;
    event(c, t, event_id).await
}
pub struct Binding {
    pub event: Event,
    pub subscription: Subscription,
    pub fingerprint: Vec<u8>,
}
pub async fn binding(c: &mut PgConnection, t: Uuid, id: Uuid) -> Result<Binding, Error> {
    let row=sqlx::query("SELECT event_id,subscription,target_version,fingerprint FROM mdm_webhook.deliveries WHERE tenant_id=$1 AND id=$2").bind(t).bind(id).fetch_optional(&mut *c).await?.ok_or(Error::NotFound)?;
    let subscription = get(c, t, row.try_get("subscription")?).await?;
    if subscription.deleted
        || !subscription.enabled
        || subscription.target_version != row.try_get::<i64, _>("target_version")?
    {
        return Err(Error::Denied);
    }
    Ok(Binding {
        event: event(c, t, row.try_get("event_id")?).await?,
        subscription,
        fingerprint: row.try_get("fingerprint")?,
    })
}
