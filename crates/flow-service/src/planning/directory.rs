use super::*;
use crate::authorization::context::AuthorizedPrincipal;
use rss_mdm_authorization_service::Permission;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};
use serde_json::json;
pub static SCHEMA: Schema = Schema {
    id: "scopes",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("deleted", Kind::Boolean),
        Field::scalar("calculationRevision", Kind::Integer),
        Field::scalar("resolutionRevision", Kind::Integer),
        Field::output("resolution"),
        Field::filter_only("ready", Kind::Boolean),
    ],
};
pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    let mut q = SCHEMA.parse(raw)?;
    q.default_filter("deleted", "false")?;
    Ok(q)
}
fn column(name: &str) -> &'static str {
    match name {
        "id" => "id::text COLLATE \"C\"",
        "revision" => "revision",
        "deleted" => "deleted",
        "calculationRevision" => "calculation_revision",
        "resolutionRevision" => "resolution_revision",
        "ready" => "(mdm_planning.scope_admission(id,NULL)->>'state'='fresh')",
        _ => unreachable!("checked Scope field"),
    }
}
impl Planning {
    pub async fn scope_directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        q.require_schema(&SCHEMA).map_err(crate::query_error)?;
        proof.manage(Permission::ScopeRead)?;
        crate::transaction::inspect(&self.runtime, self.tenant, (self, proof, q, audit), |ctx, tx| Box::pin(async move {
            let (s,p,q,_audit) = *ctx;
            let current = crate::action_admission::current(tx,p).await?;
            current.require(p,Permission::ScopeRead,None)?;
            let binding=q.binding(&(p.tenant_id(),p.instance_id(),current.query_binding(p)?)).map_err(crate::query_error)?;
            let codec=CursorCodec::from_key(s.cursor_key.clone());
            let after=q.after(&codec,&binding).map_err(crate::query_error)?;
            let mut sql=sqlx::QueryBuilder::new("SELECT jsonb_build_object('id',id,'revision',revision,'deleted',deleted,'calculationRevision',calculation_revision,'resolution',resolution,'resolutionRevision',resolution_revision) FROM mdm_planning.scopes WHERE tenant_id=");
            sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
            rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(crate::query_error)?;
            let rows:Vec<Value>=tx.with_connection(move |c| Box::pin(async move {sql.build_query_scalar().fetch_all(c).await})).await?;
            p.check_live()?;
            Ok(json!(q.page(rows,&codec,&binding).map_err(crate::query_error)?))
        }),crate::transaction::TransactionOwner::Planning).await
    }
}
