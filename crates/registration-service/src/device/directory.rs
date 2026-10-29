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
        rss_mdm_query::Error::CursorInvalidated => Error::CursorInvalidated,
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
    sql.push(") SELECT s.id,b.rows,e.summary FROM source_budget b LEFT JOIN selected s ON true LEFT JOIN mdm_access.directory_endpoints e ON e.tenant_id=$1::uuid AND e.id=s.id");
    rss_mdm_query_postgres::order(&mut sql, q, |field| match field {
        "id" => "s.id COLLATE \"C\"",
        "status" => "s.status COLLATE \"C\"",
        _ => unreachable!("checked identity ordering"),
    });
    Ok(sql)
}
impl DeviceService {
    /// Selection and the optional Inventory projection share one read-only snapshot.
    pub async fn directory<F>(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        codec: &CursorCodec,
        presence: F,
    ) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Item>>, Error>
    where
        F: for<'c> FnOnce(
                &'c mut PgConnection,
                &'c [String],
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<std::collections::BTreeSet<String>, Error>,
                        > + Send
                        + 'c,
                >,
            > + Send,
    {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.snapshot(&self.tenant).await?;
        let current = authority(&mut tx, p).await?;
        let allowed = current
            .inventory_devices(p)
            .map_err(rss_mdm_authorization_service::Error::from)?;
        let grant = current.query_binding(p)?;
        let binding = q
            .binding(&(
                "live-devices",
                p.tenant_id(),
                p.instance_id(),
                p.principal_id(),
                &grant,
            ))
            .map_err(error)?;
        let after = q.after(codec, &binding).map_err(error)?;
        let mut sql = selection(&self.tenant, allowed, q, after.as_ref(), false)?;
        let candidates: Vec<(Option<String>, i64, Option<Value>)> =
            sql.build_query_as().fetch_all(&mut *tx).await.map_err(db)?;
        check_sources(
            candidates.first().ok_or(Error::Corrupt)?.1,
            PAGE_SOURCES,
            "devices.sources",
        )?;
        let mut rows = candidates
            .into_iter()
            .filter_map(|(id, _, row)| id.map(|_| row.ok_or(Error::Corrupt)))
            .collect::<Result<Vec<_>, _>>()?;
        let more = rows.len() > q.limit();
        rows.truncate(q.limit());
        let ids = rows
            .iter()
            .map(|row| row["id"].as_str().map(str::to_owned).ok_or(Error::Corrupt))
            .collect::<Result<Vec<_>, _>>()?;
        if q.selects("inventoryAvailable") {
            let present = presence(&mut tx, &ids).await?;
            for row in &mut rows {
                row["inventoryAvailable"] =
                    json!(present.contains(row["id"].as_str().ok_or(Error::Corrupt)?));
            }
        }
        let next_cursor = if more {
            rows.last()
                .map(|row| {
                    q.position(row)
                        .and_then(|position| codec.encode(&binding, &position))
                        .map(|c| c.as_str().to_owned())
                        .map_err(error)
                })
                .transpose()?
        } else {
            None
        };
        let items = rows
            .into_iter()
            .map(|row| {
                let item: Item = serde_json::from_value(row).map_err(|_| Error::Corrupt)?;
                q.project_typed(item).map_err(error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        tx.rollback().await.map_err(db)?;
        self.access.confirm_query(p, &grant).await?;
        Ok(rss_mdm_query::Page { items, next_cursor })
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
        let mut tx = self.access.snapshot(&self.tenant).await?;
        let current = authority(&mut tx, p).await?;
        let grant = current.query_binding(p)?;
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
        tx.rollback().await.map_err(db)?;
        self.access.confirm_query(p, &grant).await?;
        serde_json::from_value(value).map_err(|_| Error::Corrupt)
    }
    pub async fn directory_device(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
    ) -> Result<Item, Error> {
        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.snapshot(&self.tenant).await?;
        let current = authority(&mut tx, p).await?;
        current
            .require(p, Permission::InventoryRead, Some(device))
            .map_err(rss_mdm_authorization_service::Error::from)?;
        let grant = current.query_binding(p)?;
        let item = self.directory_device_on(&mut tx, device).await?;
        tx.rollback().await.map_err(db)?;
        self.access.confirm_query(p, &grant).await?;
        Ok(item)
    }
    /// Read one already-authorized identity on the caller's snapshot connection.
    pub async fn directory_device_on(
        &self,
        c: &mut PgConnection,
        device: &str,
    ) -> Result<Item, Error> {
        Id::new(device).map_err(|_| Error::Malformed)?;
        let value = page_on(c, &self.tenant, &[device.to_owned()]).await?;
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
    pub status: crate::enrollment::read::RegistrationState,
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
    pub status: crate::enrollment::read::RegistrationState,
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
    pub registration_status: crate::enrollment::read::RegistrationState,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub enrollment_id: uuid::Uuid,
    pub source: Source,
    pub platform: Option<rss_mdm_agent_wire::runtime::TaskPlatform>,
    pub status: crate::enrollment::read::State,
    pub expires_at: i64,
}

#[cfg(test)]
mod response_tests {
    use super::*;
    #[test]
    fn bound_enrollment_uses_its_actual_state_owner() {
        let value = serde_json::json!({"id":"device","status":"active","primaryMdmRegistration":null,"channels":[],"enrollments":[{"enrollmentId":uuid::Uuid::new_v4(),"source":"mdm.apple","platform":"macos","status":"bound","expiresAt":1}]});
        let item: Item = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(item).unwrap(), value);
        let mut unknown = value;
        unknown["enrollments"][0]["status"] = "future".into();
        assert!(serde_json::from_value::<Item>(unknown).is_err());
    }
}
