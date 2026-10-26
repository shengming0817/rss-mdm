//! Management identity reads include issued targets without inventing registered devices.
//!
//! `channels[].lastCommunicationReceivedAt` is a nullable UTC epoch second bound
//! to that channel's primary registration ID and generation. Null means no accepted
//! Windows/Apple management exchange or Agent task poll/report has been recorded
//! for this registration. It is server receipt time, not device observation time,
//! Inventory completeness or proof that the device is currently online.
use super::*;
use crate::database::db;
use rss_mdm_authorization_service::{Permission, Snapshot};
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::{Value, json};
use sqlx::PgConnection;

pub static SCHEMA: Schema = Schema {
    id: "devices",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Text),
        Field::scalar(
            "status",
            Kind::Enum(&[
                "active",
                "pending",
                "revoked",
                "superseded",
                "registered",
                "cancelled",
                "expired",
            ]),
        ),
        Field::filter_only("channel", Kind::EnumSet(&["mdm", "agent"])),
        Field::filter_only(
            "source",
            Kind::EnumSet(&["mdm.windows", "mdm.apple", "agent.builtin"]),
        ),
        Field::output("primaryMdmRegistration"),
        Field::output("channels"),
        Field::output("enrollments"),
        Field::output("inventoryAvailable"),
    ],
};
fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
fn column(name: &str) -> &'static str {
    match name {
        "id" => "d.id COLLATE \"C\"",
        "status" => "d.status COLLATE \"C\"",
        "channel" => {
            "ARRAY(SELECT r.channel FROM mdm_access.registrations r WHERE r.tenant_id=d.tenant_id AND r.device=d.id UNION SELECT CASE WHEN q.source LIKE 'mdm.%' THEN 'mdm' ELSE 'agent' END FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE g.tenant_id=d.tenant_id AND g.device=d.id)"
        }
        "source" => {
            "ARRAY(SELECT 'agent.builtin' FROM mdm_access.registrations r WHERE r.tenant_id=d.tenant_id AND r.device=d.id AND r.channel='agent' UNION SELECT q.source FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE g.tenant_id=d.tenant_id AND g.device=d.id)"
        }
        _ => unreachable!("checked identity field"),
    }
}
async fn authority(c: &mut PgConnection, p: &AuthorizedPrincipal) -> Result<Snapshot, Error> {
    rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
        .await
        .map_err(Into::into)
}
async fn revision(c: &mut PgConnection, tenant: &str) -> Result<(i64, i64), Error> {
    sqlx::query_as("SELECT coalesce((SELECT revision FROM mdm_access.directory_revisions WHERE tenant_id=$1::uuid),0),coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)").bind(tenant).fetch_one(c).await.map_err(db)
}
async fn validity(c: &mut PgConnection, tenant: &str) -> Result<(i64, Option<i64>), Error> {
    sqlx::query_as("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint,(SELECT floor(extract(epoch FROM min(expires_at)))::bigint FROM mdm_access.requests WHERE tenant_id=$1::uuid AND state='pending' AND expires_at>statement_timestamp())").bind(tenant).fetch_one(c).await.map_err(db)
}
const PAGE_SOURCES: i64 = 1_048_576;
const STATISTICS_SOURCES: i64 = 4_194_304;
fn source_budget(tenant: &str, limit: i64, explain: bool) -> sqlx::QueryBuilder<sqlx::Postgres> {
    let mut sql = sqlx::QueryBuilder::new(if explain {
        "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "
    } else {
        ""
    });
    sql.push("WITH source_budget AS MATERIALIZED (SELECT count(*) AS rows FROM (SELECT tenant_id FROM mdm_access.directory_inputs WHERE tenant_id=").push_bind(tenant.to_owned()).push("::uuid LIMIT ").push_bind(limit+1).push(") probe) ");
    sql
}
fn check_sources(rows: i64, limit: i64, stage: &'static str) -> Result<(), Error> {
    if !rss_mdm_query_postgres::within_budget(
        stage,
        rows as u64,
        rows as u64 * 16,
        limit as u64,
        limit as u64 * 16,
    ) {
        return Err(Error::Capacity);
    }
    Ok(())
}
fn selection(
    tenant: &str,
    allowed: Option<std::collections::BTreeSet<String>>,
    q: &Query,
    after: Option<&rss_mdm_query::directory::Position>,
    explain: bool,
) -> Result<sqlx::QueryBuilder<sqlx::Postgres>, Error> {
    let mut sql = source_budget(tenant, PAGE_SOURCES, explain);
    sql.push(", selected AS (SELECT d.id,d.status FROM mdm_access.directory_metadata d WHERE (SELECT rows FROM source_budget)<=").push_bind(PAGE_SOURCES).push(" AND d.tenant_id=$1::uuid");
    if let Some(allowed) = allowed {
        sql.push(" AND d.id=ANY(")
            .push_bind(allowed.into_iter().collect::<Vec<_>>())
            .push(")");
    }
    rss_mdm_query_postgres::append(&mut sql, q, after, column).map_err(error)?;
    sql.push(") SELECT s.id,b.rows FROM source_budget b LEFT JOIN selected s ON true");
    rss_mdm_query_postgres::order(&mut sql, q, |field| match field {
        "id" => "s.id COLLATE \"C\"",
        "status" => "s.status COLLATE \"C\"",
        _ => unreachable!("checked identity ordering"),
    });
    Ok(sql)
}
/// Not serializable: HTTP must finish the read after page-only product enrichment.
pub struct PendingDirectory {
    pub items: Vec<Item>,
    next_cursor: Option<String>,
    binding: String,
}
impl DeviceService {
    pub async fn directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        codec: &CursorCodec,
    ) -> Result<PendingDirectory, Error> {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.begin(&self.tenant).await?;
        let current = authority(&mut tx, p).await?;
        let allowed = current
            .inventory_devices(p)
            .map_err(rss_mdm_authorization_service::Error::from)?;
        let grant = current.query_binding(p)?;
        let generation = revision(&mut tx, &self.tenant).await?;
        let (now, expires) = validity(&mut tx, &self.tenant).await?;
        let binding = q
            .binding(&(
                p.tenant_id(),
                p.instance_id(),
                p.principal_id(),
                &grant,
                generation,
                expires,
            ))
            .map_err(error)?;
        let after = q.after(codec, &binding).map_err(error)?;
        let mut sql = selection(&self.tenant, allowed, q, after.as_ref(), false)?;
        let candidates: Vec<(Option<String>, i64)> =
            sql.build_query_as().fetch_all(&mut *tx).await.map_err(db)?;
        let source_rows = candidates.first().ok_or(Error::Corrupt)?.1;
        check_sources(source_rows, PAGE_SOURCES, "devices.sources")?;
        let mut ids: Vec<String> = candidates.into_iter().filter_map(|(id, _)| id).collect();
        let more = ids.len() > q.limit();
        ids.truncate(q.limit());
        let raw = page_on(&mut tx, &self.tenant, &ids).await?;
        let mut by_id = raw["items"]
            .as_array()
            .ok_or(Error::Corrupt)?
            .iter()
            .map(|r| {
                Ok((
                    r["id"].as_str().ok_or(Error::Corrupt)?.to_owned(),
                    r.clone(),
                ))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, Error>>()?;
        let rows = ids
            .iter()
            .map(|id| by_id.remove(id).ok_or(Error::Conflict))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if more {
            rows.last()
                .map(|r| {
                    q.position(r)
                        .and_then(|position| codec.encode(&binding, &position))
                        .map(|c| c.as_str().to_owned())
                        .map_err(error)
                })
                .transpose()?
        } else {
            None
        };
        let end = authority(&mut tx, p).await?;
        let (final_now, final_expiry) = validity(&mut tx, &self.tenant).await?;
        if grant != end.query_binding(p)?
            || generation != revision(&mut tx, &self.tenant).await?
            || expires != final_expiry
            || expires.is_some_and(|t| t <= final_now)
            || final_now < now
        {
            return Err(Error::Conflict);
        }
        p.check_live()?;
        Ok(PendingDirectory {
            items: rows
                .into_iter()
                .map(|row| serde_json::from_value(row).map_err(|_| Error::Corrupt))
                .collect::<Result<Vec<_>, _>>()?,
            next_cursor,
            binding,
        })
    }
    pub async fn finish_directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        pending: PendingDirectory,
    ) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Item>>, Error> {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.begin(&self.tenant).await?;
        let current = authority(&mut tx, p).await?;
        let generation = revision(&mut tx, &self.tenant).await?;
        let (now, expires) = validity(&mut tx, &self.tenant).await?;
        let binding = q
            .binding(&(
                p.tenant_id(),
                p.instance_id(),
                p.principal_id(),
                current.query_binding(p)?,
                generation,
                expires,
            ))
            .map_err(error)?;
        if binding != pending.binding || expires.is_some_and(|v| v <= now) {
            return Err(Error::Conflict);
        }
        let items = pending
            .items
            .into_iter()
            .map(|row| q.project_typed(row).map_err(error))
            .collect::<Result<Vec<_>, _>>()?;
        p.check_live()?;
        Ok(rss_mdm_query::Page {
            items,
            next_cursor: pending.next_cursor,
        })
    }
    /// Real provider plan for the exact production candidate selector, with live tenant authorization.
    #[cfg(feature = "integration")]
    pub async fn directory_plan(&self, p: &AuthorizedPrincipal, q: &Query) -> Result<Value, Error> {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant || q.cursor().is_some() {
            return Err(Error::Malformed);
        }
        let mut tx = self.access.begin(&self.tenant).await?;
        let current = authority(&mut tx, p).await?;
        let allowed = current
            .inventory_devices(p)
            .map_err(rss_mdm_authorization_service::Error::from)?;
        let mut sql = selection(&self.tenant, allowed, q, None, true)?;
        sql.build_query_scalar()
            .fetch_one(&mut *tx)
            .await
            .map_err(db)
    }
    pub async fn directory_statistics(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
    ) -> Result<rss_mdm_query::Statistics<DeviceStatistics>, Error> {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.begin(&self.tenant).await?;
        let current = authority(&mut tx, p).await?;
        let grant = current.query_binding(p)?;
        let generation = revision(&mut tx, &self.tenant).await?;
        let mut sql = source_budget(&self.tenant, STATISTICS_SOURCES, false);
        sql.push("SELECT b.rows,CASE WHEN b.rows<=").push_bind(STATISTICS_SOURCES).push(" THEN (SELECT jsonb_build_object('statistics',jsonb_build_object('total',count(*),'pending',count(*) FILTER(WHERE d.status='pending'),'active',count(*) FILTER(WHERE d.status='active'),'revoked',count(*) FILTER(WHERE d.status='revoked')),'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint) FROM mdm_access.directory_metadata d WHERE d.tenant_id=$1::uuid");
        if let Some(allowed) = current
            .inventory_devices(p)
            .map_err(rss_mdm_authorization_service::Error::from)?
        {
            sql.push(" AND d.id=ANY(")
                .push_bind(allowed.into_iter().collect::<Vec<_>>())
                .push(")");
        }
        rss_mdm_query_postgres::filter(&mut sql, q, column).map_err(error)?;
        sql.push(") END FROM source_budget b");
        let (source_rows, value): (i64, Option<Value>) =
            sql.build_query_as().fetch_one(&mut *tx).await.map_err(db)?;
        check_sources(
            source_rows,
            STATISTICS_SOURCES,
            "devices.statistics.sources",
        )?;
        let value = value.ok_or(Error::Corrupt)?;
        if grant != authority(&mut tx, p).await?.query_binding(p)?
            || generation != revision(&mut tx, &self.tenant).await?
        {
            return Err(Error::Conflict);
        }
        p.check_live()?;
        serde_json::from_value(value).map_err(|_| Error::Corrupt)
    }
    pub async fn directory_device(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
    ) -> Result<Item, Error> {
        Id::new(device).map_err(|_| Error::Malformed)?;
        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.begin(&self.tenant).await?;
        authority(&mut tx, p)
            .await?
            .require(p, Permission::InventoryRead, Some(device))
            .map_err(rss_mdm_authorization_service::Error::from)?;
        let value = page_on(&mut tx, &self.tenant, &[device.to_owned()]).await?;
        p.check_live()?;
        value["items"]
            .as_array()
            .and_then(|v| v.first())
            .cloned()
            .ok_or(Error::NotFound)
            .and_then(|value| serde_json::from_value(value).map_err(|_| Error::Corrupt))
    }
}
/// Hydrate an already authorized page. This API cannot enumerate a tenant.
pub async fn page_on(
    c: &mut PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<Value, Error> {
    if devices.len() > 1000 {
        return Err(Error::Malformed);
    }
    let rows=sqlx::query("SELECT d.summary FROM unnest($2::text[]) WITH ORDINALITY p(id,n) JOIN mdm_access.directory_endpoints d ON d.id=p.id WHERE d.tenant_id=$1::uuid ORDER BY p.n").bind(tenant).bind(devices).fetch_all(c).await.map_err(db)?;
    rss_mdm_query_postgres::observe_rows("device.identity", &rows).map_err(db)?;
    use sqlx::Row;
    let items = rows
        .iter()
        .map(|r| r.try_get::<Value, _>(0).map_err(db))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({"items":items}))
}

#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct DeviceStatistics {
    pub total: u64,
    pub pending: u64,
    pub active: u64,
    pub revoked: u64,
}

#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub status: Status,
    pub primary_mdm_registration: Option<Primary>,
    pub channels: Vec<Channel>,
    pub enrollments: Vec<Enrollment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_available: Option<bool>,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    Pending,
    Revoked,
    Superseded,
    Registered,
    Cancelled,
    Expired,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
pub enum Source {
    #[serde(rename = "mdm.windows")]
    Windows,
    #[serde(rename = "mdm.apple")]
    Apple,
    #[serde(rename = "agent.builtin")]
    Agent,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Primary {
    pub registration_id: uuid::Uuid,
    pub generation: i64,
    pub source: Source,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub registration_id: uuid::Uuid,
    pub channel: rss_mdm_inventory::Channel,
    pub generation: i64,
    pub status: Status,
    pub source: Source,
    pub platform: Option<rss_mdm_agent_wire::runtime::TaskPlatform>,
    pub last_communication_received_at: Option<i64>,
    pub children: Vec<Child>,
    pub user_context: Option<UserContext>,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Child {
    pub registration_id: uuid::Uuid,
    pub purpose: String,
    pub generation: i64,
    pub status: Status,
    pub ready: bool,
    pub parent_registration_id: uuid::Uuid,
    pub parent_generation: i64,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserContext {
    pub id: uuid::Uuid,
    pub parent_registration_id: uuid::Uuid,
    pub parent_generation: i64,
    pub registration_status: Status,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub enrollment_id: uuid::Uuid,
    pub source: Source,
    pub platform: Option<rss_mdm_agent_wire::runtime::TaskPlatform>,
    pub status: Status,
    pub expires_at: i64,
}
