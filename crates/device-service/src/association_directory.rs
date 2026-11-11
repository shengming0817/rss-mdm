//! Current association discovery; membership authorization is evaluated before paging.
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Query, Schema},
};

use std::time::Duration;
use uuid::Uuid;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema::derived::<AssociationRow>("device_associations", &["id"], 64, 100, &[rss_mdm_query::directory::Exclusion { path: "association.members", reason: "Member object arrays require device and channel to match the same member" }, rss_mdm_query::directory::Exclusion { path: "association.state", reason: "Effective state is recomputed from current hardware evidence and competitor qualification; the stored association state is not this public value" }]).expect("Public directory model"));
impl Associations {
    pub async fn directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
    ) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<AssociationRow>>> {
        q.require_schema(&SCHEMA).map_err(|_| Error::Malformed)?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let budget = AuditBudget::new(Duration::from_secs(15));
        let (page,grants)=self.audit.read(self.tenant,&budget.control(),(self,p,q),|ctx,tx|Box::pin(async move {
            tx.with_connection_context(ctx,|(s,p,q),c|Box::pin(async move {
                let current=read::authorization(c,p).await?;
                let allowed=current.inventory_devices(p)?;
                let binding=q.binding(&("live-associations",p.tenant_id(),p.instance_id(),p.principal_id(),current.query_binding(p)?)).map_err(|_|Error::Malformed)?;
                let codec=CursorCodec::from_key(s.key.clone());
                let after=q.after(&codec,&binding).map_err(|_|Error::CursorInvalidated)?;
                let mut sql=sqlx::QueryBuilder::new("WITH selected AS MATERIALIZED (SELECT a.* FROM mdm_devices.associations a WHERE a.tenant_id=");
                sql.push_bind(p.tenant_id().to_owned()).push("::uuid");
                if let Some(ids)=allowed {
                    sql.push(" AND NOT EXISTS(SELECT FROM mdm_devices.members m WHERE m.tenant_id=a.tenant_id AND m.association_id=a.id AND NOT(m.device=ANY(").push_bind(ids.into_iter().collect::<Vec<_>>()).push(")))");
                }
                rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),&*BINDINGS).map_err(|_|Error::Malformed)?;
                sql.push(") SELECT jsonb_build_object('world',mdm_devices.read_world(ARRAY(SELECT id FROM selected),ARRAY(SELECT DISTINCT m.device FROM mdm_devices.members m JOIN selected s ON s.id=m.association_id WHERE m.tenant_id=$1::uuid),ARRAY[]::text[]),'ids',ARRAY(SELECT a.id FROM selected a");
                rss_mdm_query_postgres::order(&mut sql,q,&*BINDINGS).map_err(|_|Error::Malformed)?;
                sql.push("))");
                let raw:serde_json::Value=sql.build_query_scalar().fetch_one(c).await?;
                let ids=raw["world"]["endpoints"].as_array().ok_or(Error::Storage)?.iter().map(|v|v["id"].as_str().map(str::to_owned).ok_or(Error::Storage)).collect::<Result<Vec<_>>>()?;
                let (world,_,_,_)=crate::snapshot::decode_world(&raw["world"],s.tenant,&ids)?;
                let mut by_id=world.associations.iter().map(|a| { let a=world.effective(a.clone());(a.id,AssociationRow{id:a.id,version:a.version,confirmed_at:a.confirmed_at,association:a}) }).collect::<std::collections::BTreeMap<_,_>>();
                let selected: Vec<Uuid> = serde_json::from_value(raw["ids"].clone()).map_err(|_|Error::Storage)?;
                let rows=selected.into_iter().map(|id|by_id.remove(&id).ok_or(Error::Storage)).collect::<Result<Vec<_>>>()?;
                p.check_live()?;
                Ok((q.page_typed(rows,&codec,&binding).map_err(|_|Error::Malformed)?,current.query_binding(p)?))
            })).await
        })).await.fold(Ok,|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::Storage),|e|Err(model::transaction_error(e)))?;
        self.confirm_scope(p, &grants, None, &budget).await?;
        Ok(page)
    }
}

pub static CANDIDATES: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "device_association_candidates",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "candidate device identity",
    context: &["channel"],
};
pub static SOURCE_ITEMS: rss_mdm_query::window::Schema = rss_mdm_query::window::Schema {
    id: "device_view_items",
    default_limit: rss_mdm_query::DEFAULT_PAGE_LIMIT,
    max_limit: rss_mdm_query::MAX_PAGE_LIMIT,
    order: "immutable source array ordinal",
    context: &[],
};

#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssociationRow {
    pub id: Uuid,
    pub version: i64,
    pub confirmed_at: i64,
    pub association: Association,
}

pub static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(|| rss_mdm_query_postgres::Bindings::new(&SCHEMA, &[rss_mdm_query_postgres::Source::required_column("id", "a.id::text COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("version", "a.version"),
rss_mdm_query_postgres::Source::column("confirmedAt", "a.confirmed_at"),
rss_mdm_query_postgres::Source::json("association", "jsonb_build_object('id',a.id,'version',a.version,'evidence',a.evidence,'confirmedBy',a.confirmed_by,'confirmedAt',a.confirmed_at,'revokedBy',a.revoked_by,'revokedAt',a.revoked_at,'reason',a.reason)")]).expect("Complete public model storage binding"));
