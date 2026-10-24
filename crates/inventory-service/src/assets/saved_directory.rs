use super::*;
use crate::authorization::context::AuthorizedPrincipal;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
pub static SCHEMA: Schema = Schema {
    id: "saved_queries",
    keys: &["id"],
    default_limit: 100,
    max_limit: 100,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("name", Kind::Text),
        Field::scalar("deleted", Kind::Boolean),
        Field::output("definition"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "id::text COLLATE \"C\"",
        "revision" => "revision",
        "name" => "(document->>'name') COLLATE \"C\"",
        "deleted" => "(document IS NULL)",
        _ => unreachable!("checked saved query field"),
    }
}
impl AssetService {
    pub async fn saved_directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        q.require_schema(&SCHEMA).map_err(crate::query_error)?;
        ReadScope::from_proof(p)?;
        audit.set_action("asset_read");
        crate::transaction::inspect(&self.runtime,self.tenant,(self,p,q,audit),|ctx,tx|Box::pin(async move{
   let(s,p,q,audit)=*ctx;let current=query_authority(tx,p).await?;
   // Saved queries are personal documents, not a directory of device facts.
   current.inventory_devices(p)?;
   let binding=q.binding(&(p.tenant_id(),p.instance_id(),p.principal_id(),current.query_binding(p)?)).map_err(crate::query_error)?;
   let codec=CursorCodec::from_key(s.asset_cursor_key.clone());let after=q.after(&codec,&binding).map_err(crate::query_error)?;
   let mut sql=sqlx::QueryBuilder::new("SELECT jsonb_build_object('id',id,'revision',revision,'definition',document,'name',document->>'name','deleted',document IS NULL) FROM mdm_assets.saved_queries WHERE tenant_id=");
   sql.push_bind(tx.tenant_id().to_string()).push("::uuid AND instance=").push_bind(p.instance_id().to_owned()).push("::uuid AND owner=").push_bind(p.principal_id().to_owned()).push("::uuid");
   rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(crate::query_error)?;
   let rows:Vec<Value>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_scalar().fetch_all(c).await})).await?;
   for row in &rows{if !row["definition"].is_null(){let _:SavedDefinition=stored(serde_json::from_value(row["definition"].clone()))?;}}
   let page=q.page(rows,&codec,&binding).map_err(crate::query_error)?;
   p.check_live()?;audit.require_request_settlement();json(&AssetEnvelope{tenant_id:p.tenant_id().into(),asset:Response::SavedList{items:page.items,next_cursor:page.next_cursor}})
  }),crate::transaction::TransactionOwner::Assets).await
    }
}
