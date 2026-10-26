//! Current association discovery; membership authorization is evaluated before paging.
use crate::*;
use rss_mdm_audit_integration::budget::AuditBudget;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};

use std::time::Duration;
use uuid::Uuid;
pub static SCHEMA: Schema = Schema {
    id: "device_associations",
    keys: &["id"],
    default_limit: 64,
    max_limit: 100,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("version", Kind::Integer),
        Field::scalar("confirmedAt", Kind::Integer),
        Field::output("association"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "a.id::text COLLATE \"C\"",
        "version" => "a.version",
        "confirmedAt" => "a.confirmed_at",
        _ => unreachable!("checked association field"),
    }
}
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
        self.audit.write(self.tenant,&budget.source_control(),(self,p,q),|ctx,tx|Box::pin(async move{
   tx.with_connection_context(ctx,|(s,p,q),c|Box::pin(async move{
    rss_mdm_inventory_postgres::lock_watermark_in(c,s.tenant).await?;
    let current=read::authorization(c,p).await?;
    let allowed=current.inventory_devices(p)?;
    let generation=directory::read_generation(c,p.tenant_id()).await?;
    let grant=current.query_binding(p)?;
    let binding=q.binding(&(p.tenant_id(),p.instance_id(),p.principal_id(),&grant,&generation)).map_err(|_|Error::Malformed)?;
    let codec=CursorCodec::from_key(s.key.clone());
    let after=q.after(&codec,&binding).map_err(|_|Error::CursorInvalidated)?;
    let mut sql=sqlx::QueryBuilder::new("SELECT a.id FROM mdm_devices.associations a WHERE a.tenant_id=");
    sql.push_bind(p.tenant_id().to_owned()).push("::uuid");
    if let Some(ids)=allowed{sql.push(" AND NOT EXISTS(SELECT 1 FROM mdm_devices.members m WHERE m.tenant_id=a.tenant_id AND m.association_id=a.id AND NOT(m.device=ANY(").push_bind(ids.into_iter().collect::<Vec<_>>()).push(")))");}
    rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(|_|Error::Malformed)?;
    let ids:Vec<Uuid>=sql.build_query_scalar().fetch_all(&mut *c).await?;
    let associations=read::load_page(c,p.tenant_id(),&ids).await?;
    let devices=associations.iter().flat_map(|a|a.members.iter().map(|m|m.device.clone())).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>();
    let world=identity::local_world(c,s.tenant,&devices,&ids).await?;
    let mut rows=std::collections::BTreeMap::new();
    for a in associations {let a=world.effective(a);rows.insert(a.id,AssociationRow {id:a.id,version:a.version,confirmed_at:a.confirmed_at,association:a});}
    let rows=ids.iter().map(|id|rows.remove(id).ok_or(Error::Storage)).collect::<Result<Vec<_>>>()?;
    if generation!=directory::read_generation(c,p.tenant_id()).await?||grant!=read::authorization(c,p).await?.query_binding(p)?{return Err(Error::CursorInvalidated);}
    p.check_live()?;
    q.page_typed(rows,&codec,&binding).map_err(|_|Error::Malformed)
   })).await
  })).await.fold(Ok,|e|Err(model::transaction_error(e)),|e|Err(model::transaction_error(e)),|_|Err(Error::RollbackFailed),|_|Err(Error::CommitUnknown),|e|Err(model::transaction_error(e)))
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
