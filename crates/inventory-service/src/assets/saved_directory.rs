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

/// The installer rebuilds only this projection from the current canonical AST and formatter.
/// It borrows the installation transaction and never commits or weakens RLS.
pub async fn rebuild_filter_text(
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
) -> std::result::Result<(), sqlx::Error> {
    let previous: String =
        sqlx::query_scalar("SELECT coalesce(current_setting('rss.tenant_id',true),'')")
            .fetch_one(&mut *c)
            .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *c)
        .await?;
    let mut after: Option<(Uuid, Uuid, Uuid)> = None;
    loop {
        let rows: Vec<(Uuid, Uuid, Uuid, Value)> = sqlx::query_as("SELECT instance,owner,id,document FROM mdm_assets.saved_queries WHERE tenant_id=$1 AND document IS NOT NULL AND ($2::uuid IS NULL OR (instance,owner,id)>($2,$3,$4)) ORDER BY instance,owner,id LIMIT 128")
            .bind(tenant).bind(after.map(|v|v.0)).bind(after.map(|v|v.1)).bind(after.map(|v|v.2)).fetch_all(&mut *c).await?;
        if rows.is_empty() {
            break;
        }
        for (instance, owner, id, document) in rows {
            let definition: rsql::StoredDefinition = serde_json::from_value(document)
                .map_err(|_| sqlx::Error::Protocol("saved query projection input".into()))?;
            let text = definition
                .into_view()
                .map_err(|_| sqlx::Error::Protocol("saved query projection format".into()))?
                .query
                .filter;
            sqlx::query("UPDATE mdm_assets.saved_queries SET filter_text=$5 WHERE tenant_id=$1 AND instance=$2 AND owner=$3 AND id=$4")
                .bind(tenant).bind(instance).bind(owner).bind(id).bind(text).execute(&mut *c).await?;
            after = Some((instance, owner, id));
        }
    }
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(previous)
        .execute(&mut *c)
        .await?;
    Ok(())
}
