use super::*;
use crate::authorization::context::AuthorizedPrincipal;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Exclusion, Query, Schema},
};
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Row>(
        "saved_queries",
        &["id"],
        100,
        100,
        &[Exclusion {
            path: "definition.query.sort",
            reason: "Sort object arrays require field and direction to match the same element",
        }],
    )
    .expect("Saved query public model is fully described")
});
static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> = std::sync::LazyLock::new(
    || {
        use rss_mdm_query_postgres::{Bindings, Source};
        Bindings::new(&SCHEMA, &[
        Source::column("id", "id::text COLLATE \"C\""),
        Source::column("revision", "revision"),
        Source::column("name", "(document->>'name') COLLATE \"C\""),
        Source::column("deleted", "document IS NULL"),
        Source::column("definition.name", "(document->>'name') COLLATE \"C\""),
        Source::column("definition.query.filter", "filter_text COLLATE \"C\""),
        Source::json("definition.query.fields", "document->'query'->'fields'"),
        Source::json("definition.query.scope", "CASE WHEN document IS NULL THEN NULL WHEN document->'query'->'criteria' IS NULL OR document->'query'->'criteria'='null'::jsonb THEN '{\"selector\":{\"kind\":\"device\"},\"quantifier\":\"one\"}'::jsonb ELSE jsonb_build_object('selector',document->'query'->'criteria'->'selector','quantifier',document->'query'->'criteria'->'quantifier') END"),
    ]).expect("Saved query storage binds every public scalar")
    },
);
pub fn schema() -> &'static Schema {
    BINDINGS.schema()
}
impl AssetService {
    pub async fn saved_directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<AssetEnvelope, Error> {
        q.require_schema(schema()).map_err(crate::query_error)?;
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
   let mut sql=sqlx::QueryBuilder::new("SELECT jsonb_build_object('id',id,'revision',revision,'definition',document,'name',document->>'name','deleted',document IS NULL,'filterText',filter_text) FROM mdm_assets.saved_queries WHERE tenant_id=");
   sql.push_bind(tx.tenant_id().to_string()).push("::uuid AND instance=").push_bind(p.instance_id().to_owned()).push("::uuid AND owner=").push_bind(p.principal_id().to_owned()).push("::uuid");
   rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),&*BINDINGS).map_err(crate::query_error)?;
   let mut rows:Vec<Value>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_scalar().fetch_all(c).await})).await?;
   for row in &mut rows {
       let filter_text = row.as_object_mut().ok_or(Error::Malformed)?.remove("filterText").ok_or(Error::Malformed)?;
       if !row["definition"].is_null() {
           let definition:rsql::StoredDefinition=stored(serde_json::from_value(row["definition"].take()))?;
           let view = definition.into_view()?;
           if filter_text != serde_json::json!(view.query.filter) { return Err(Error::Unavailable(Failure::AssetsStorage).into()); }
           row["definition"]=stored(serde_json::to_value(view))?;
       } else if !filter_text.is_null() { return Err(Error::Unavailable(Failure::AssetsStorage).into()); }
   }
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
