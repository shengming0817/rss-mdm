use super::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
pub use rss_mdm_group_postgres::directory::DirectoryQuery;
impl Groups {
    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &DirectoryQuery,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        proof.manage(Permission::GroupRead)?;
        proof.require_all_devices(Permission::InventoryRead)?;
        crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,audit,(self,proof,q,audit),|ctx,tx|Box::pin(async move {
            let (s,p,q,audit)=*ctx;p.manage(Permission::GroupRead)?;p.require_all_devices(Permission::InventoryRead)?;
            let mut groups=group_checked(s.groups.directory_in(tx,q).await?)?;
            let more=groups.len()>q.limit;groups.truncate(q.limit);let next=if more{groups.last().map(|g|g.id.to_string())}else{None};
            let items=groups.iter().map(|g|serde_json::json!({"id":g.id,"kind":g.kind,"name":g.name,"description":g.description,"revision":g.revision,"calculationRevision":g.calculation_revision,"memberVersion":g.member_version,"memberCount":g.member_count,"ruleVersion":g.rule_version,"deleted":g.deleted})).collect::<Vec<_>>();
            p.check_live()?;s.audit_store.append_request_in(tx,audit,200,"success").await?;
            Ok(serde_json::json!({"items":items,"nextCursor":next}))
        }),crate::transaction::TransactionOwner::Assets).await
    }
}
