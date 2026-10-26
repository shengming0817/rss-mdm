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
    ) -> std::result::Result<AssetEnvelope, Error> {
        q.require_schema(&SCHEMA).map_err(crate::query_error)?;
        ReadScope::from_proof(p)?;
        audit.set_action(
            "asset_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        crate::transaction::inspect(&self.runtime,self.tenant,(self,p,q,audit),|ctx,tx|Box::pin(async move{
   let(s,p,q,_audit)=*ctx;let current=query_authority(tx,p).await?;
   // Saved queries are personal documents, not a directory of device facts.
   current.inventory_devices(p)?;
   let binding=q.binding(&(p.tenant_id(),p.instance_id(),p.principal_id(),current.query_binding(p)?)).map_err(crate::query_error)?;
   let codec=CursorCodec::from_key(s.asset_cursor_key.clone());let after=q.after(&codec,&binding).map_err(crate::query_error)?;
   let mut sql=sqlx::QueryBuilder::new("SELECT jsonb_build_object('id',id,'revision',revision,'definition',document,'name',document->>'name','deleted',document IS NULL) FROM mdm_assets.saved_queries WHERE tenant_id=");
   sql.push_bind(tx.tenant_id().to_string()).push("::uuid AND instance=").push_bind(p.instance_id().to_owned()).push("::uuid AND owner=").push_bind(p.principal_id().to_owned()).push("::uuid");
   rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(crate::query_error)?;
   let mut rows:Vec<Value>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_scalar().fetch_all(c).await})).await?;
   for row in &mut rows{if !row["definition"].is_null(){let definition:rsql::StoredDefinition=stored(serde_json::from_value(row["definition"].take()))?;row["definition"]=stored(serde_json::to_value(definition.into_view()?))?;}}
   let rows=stored(rows.into_iter().map(serde_json::from_value::<Row>).collect::<std::result::Result<Vec<_>,_>>())?;
   let page=q.page_typed(rows,&codec,&binding).map_err(crate::query_error)?;
   p.check_live()?;Ok(AssetEnvelope{tenant_id:p.tenant_id().into(),asset:Response::SavedList{items:page.items,next_cursor:page.next_cursor}})
  }),crate::transaction::TransactionOwner::Assets).await
    }
}

/// Full SQL directory row, decoded before projection so selected null stays distinct from absence.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub id: Uuid,
    pub revision: i64,
    pub name: Option<String>,
    pub deleted: bool,
    pub definition: Option<SavedDefinition>,
}
