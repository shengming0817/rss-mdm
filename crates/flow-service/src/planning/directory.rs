use super::*;
use crate::authorization::context::AuthorizedPrincipal;
use serde::Deserialize;
use serde_json::json;
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeQuery {
    pub after: Option<Uuid>,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub descending: bool,
    #[serde(default)]
    pub deleted: bool,
    pub ready: Option<bool>,
}
fn limit() -> usize {
    64
}
impl Planning {
    pub async fn group_directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &rss_mdm_inventory_service::groups::directory::DirectoryQuery,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        self.inventory_groups()
            .directory(proof, q, audit)
            .await
            .map_err(Into::into)
    }
    pub async fn scope_directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &ScopeQuery,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        if !(1..=1000).contains(&q.limit) || q.after.is_some_and(|v| v.is_nil()) {
            return Err(Error::Malformed);
        }
        proof.manage(Permission::ScopeRead)?;
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,q,audit),|ctx,tx|Box::pin(async move {
            let (s,p,q,audit)=*ctx;p.manage(Permission::ScopeRead)?;let tenant=tx.tenant_id().to_string();let query=q.clone();
            let mut items:Vec<Value>=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar("SELECT jsonb_build_object('id',id,'revision',revision,'deleted',deleted,'calculationRevision',calculation_revision,'resolution',resolution,'resolutionRevision',resolution_revision) FROM mdm_planning.scopes WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR CASE WHEN $3 THEN id<$2 ELSE id>$2 END) AND deleted=$4 AND ($5::boolean IS NULL OR (resolution IS NOT NULL)=$5) ORDER BY CASE WHEN NOT $3 THEN id END ASC,CASE WHEN $3 THEN id END DESC LIMIT $6")
                    .bind(tenant).bind(query.after).bind(query.descending).bind(query.deleted).bind(query.ready).bind((query.limit+1) as i64).fetch_all(c).await
            })).await?;
            let more=items.len()>q.limit;items.truncate(q.limit);let next=if more{items.last().map(|v|v["id"].clone())}else{None};
            p.check_live()?;s.audit_store.append_request_in(tx,audit,200,"success").await?;
            Ok(json!({"items":items,"nextCursor":next}))
        }),crate::transaction::TransactionOwner::Planning).await
    }
}
