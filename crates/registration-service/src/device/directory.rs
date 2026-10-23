//! Management identity reads include issued targets without inventing registered devices.
//!
//! `channels[].lastCommunicationReceivedAt` is a nullable UTC epoch second bound
//! to that channel's primary registration ID and generation. Null means no accepted
//! Windows/Apple management exchange or Agent task poll/report has been recorded
//! for this registration. It is server receipt time, not device observation time,
//! Inventory completeness or proof that the device is currently online.
use super::*;
use crate::database::db;
use rss_mdm_authorization_service::Permission;
use serde_json::Value;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub after: Option<String>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    pub status: Option<String>,
    pub channel: Option<Channel>,
    pub source: Option<ReportSource>,
}
fn limit() -> usize {
    64
}
impl Query {
    fn validate(&self) -> Result<(), Error> {
        if !(1..=1000).contains(&self.limit)
            || self.after.as_ref().is_some_and(|id| Id::new(id).is_err())
            || self.status.as_deref().is_some_and(|s| {
                ![
                    "active",
                    "pending",
                    "revoked",
                    "superseded",
                    "registered",
                    "cancelled",
                    "expired",
                ]
                .contains(&s)
            })
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}
const DIRECTORY: &str = r#"
WITH heads AS (SELECT id,status,summary FROM mdm_access.directory_endpoints WHERE tenant_id=$1::uuid AND ($2::text[] IS NULL OR id=ANY($2))), filtered AS (
 SELECT * FROM heads d WHERE ($3::text IS NULL OR status=$3)
 AND ($4::text IS NULL OR EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.device=d.id AND r.channel=$4)
 OR EXISTS(SELECT 1 FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=$1::uuid AND g.device=d.id AND CASE WHEN q.source LIKE 'mdm.%' THEN 'mdm' ELSE 'agent' END=$4))
 AND ($5::text IS NULL OR ($5='agent.builtin' AND EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=$1::uuid AND r.device=d.id AND r.channel='agent')) OR EXISTS(SELECT 1 FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=$1::uuid AND g.device=d.id AND q.source=$5))
), page AS (
 SELECT * FROM filtered WHERE ($6::text IS NULL OR CASE WHEN $7 THEN id COLLATE "C"<$6 COLLATE "C" ELSE id COLLATE "C">$6 COLLATE "C" END)
 ORDER BY CASE WHEN NOT $7 THEN id END COLLATE "C" ASC, CASE WHEN $7 THEN id END COLLATE "C" DESC LIMIT $8
)
SELECT jsonb_build_object('items',coalesce((SELECT jsonb_agg(d.summary
 ORDER BY CASE WHEN NOT $7 THEN d.id END COLLATE "C" ASC, CASE WHEN $7 THEN d.id END COLLATE "C" DESC) FROM page d),'[]'::jsonb),
 'statistics',(SELECT jsonb_build_object('total',count(*),'pending',count(*) FILTER(WHERE status='pending'),'active',count(*) FILTER(WHERE status='active'),'revoked',count(*) FILTER(WHERE status='revoked')) FROM filtered),
 'asOf',floor(extract(epoch FROM statement_timestamp()))::bigint)
"#;
impl DeviceService {
    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        query: &Query,
    ) -> Result<Value, Error> {
        query.validate()?;
        if proof.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let allowed = proof
            .authorization()?
            .inventory_devices(proof)
            .map_err(rss_mdm_authorization_service::Error::from)?;
        let mut tx = self.access.begin(&self.tenant).await?;
        let mut value: Value = sqlx::query_scalar(DIRECTORY)
            .bind(&self.tenant)
            .bind(allowed.map(|ids| ids.into_iter().collect::<Vec<_>>()))
            .bind(&query.status)
            .bind(query.channel.map(|v| v.as_str()))
            .bind(query.source.map(|v| v.as_str()))
            .bind(&query.after)
            .bind(query.descending)
            .bind((query.limit + 1) as i64)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let items = value["items"].as_array_mut().ok_or(Error::Corrupt)?;
        let more = items.len() > query.limit;
        items.truncate(query.limit);
        let next = if more {
            items.last().map(|item| item["id"].clone())
        } else {
            None
        };
        value["nextCursor"] = next.unwrap_or(Value::Null);
        proof.check_live()?;
        Ok(value)
    }
    pub async fn directory_device(
        &self,
        proof: &AuthorizedPrincipal,
        device: &str,
    ) -> Result<Value, Error> {
        Id::new(device).map_err(|_| Error::Malformed)?;
        proof.require(Permission::InventoryRead, Some(device))?;
        if proof.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.access.begin(&self.tenant).await?;
        let value: Value = sqlx::query_scalar(DIRECTORY)
            .bind(&self.tenant)
            .bind(Some(vec![device.to_owned()]))
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .bind(false)
            .bind(1_i64)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        proof.check_live()?;
        value["items"]
            .as_array()
            .and_then(|v| v.first())
            .cloned()
            .ok_or(Error::NotFound)
    }
}

/// Hydrate one already authorized endpoint page; this entry cannot enumerate a tenant.
pub async fn page_on(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<Value, Error> {
    if devices.len() > 200 {
        return Err(Error::Malformed);
    }
    sqlx::query_scalar(DIRECTORY)
        .bind(tenant)
        .bind(devices)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(false)
        .bind(200_i64)
        .fetch_one(c)
        .await
        .map_err(db)
}
