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
fn selection(
    tenant: &str,
    allowed: Option<std::collections::BTreeSet<String>>,
    q: &Query,
    after: Option<&rss_mdm_query::directory::Position>,
    explain: bool,
) -> Result<sqlx::QueryBuilder<sqlx::Postgres>, Error> {
    let mut sql = sqlx::QueryBuilder::new(if explain {
        "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT d.id FROM mdm_access.directory_metadata d WHERE d.tenant_id="
    } else {
        "SELECT d.id FROM mdm_access.directory_metadata d WHERE d.tenant_id="
    });
    sql.push_bind(tenant.to_owned()).push("::uuid");
    if let Some(allowed) = allowed {
        sql.push(" AND d.id=ANY(")
            .push_bind(allowed.into_iter().collect::<Vec<_>>())
            .push(")");
    }
    rss_mdm_query_postgres::append(&mut sql, q, after, column).map_err(error)?;
    Ok(sql)
}
/// Not serializable: HTTP must finish the read after page-only product enrichment.
pub struct PendingDirectory {
    pub items: Vec<Value>,
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
        let mut ids: Vec<String> = sql
            .build_query_scalar()
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
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
            items: rows,
            next_cursor,
            binding,
        })
    }
    pub async fn finish_directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        pending: PendingDirectory,
    ) -> Result<rss_mdm_query::Page<Value>, Error> {
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
            .map(|row| q.project(row).map_err(error))
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
    ) -> Result<Value, Error> {
        q.require_schema(&SCHEMA).map_err(error)?;
        if p.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.begin(&self.tenant).await?;
        let current = authority(&mut tx, p).await?;
        let grant = current.query_binding(p)?;
        let generation = revision(&mut tx, &self.tenant).await?;
        let mut sql = sqlx::QueryBuilder::new(
            "SELECT jsonb_build_object('statistics',jsonb_build_object('total',count(*),'pending',count(*) FILTER(WHERE d.status='pending'),'active',count(*) FILTER(WHERE d.status='active'),'revoked',count(*) FILTER(WHERE d.status='revoked')),'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint) FROM mdm_access.directory_metadata d WHERE d.tenant_id=",
        );
        sql.push_bind(self.tenant.clone()).push("::uuid");
        if let Some(allowed) = current
            .inventory_devices(p)
            .map_err(rss_mdm_authorization_service::Error::from)?
        {
            sql.push(" AND d.id=ANY(")
                .push_bind(allowed.into_iter().collect::<Vec<_>>())
                .push(")");
        }
        rss_mdm_query_postgres::filter(&mut sql, q, column).map_err(error)?;
        let value = sql
            .build_query_scalar()
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if grant != authority(&mut tx, p).await?.query_binding(p)?
            || generation != revision(&mut tx, &self.tenant).await?
        {
            return Err(Error::Conflict);
        }
        p.check_live()?;
        Ok(value)
    }
    pub async fn directory_device(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
    ) -> Result<Value, Error> {
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
