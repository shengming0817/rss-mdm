use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
pub use pg::directory::DirectoryQuery;
impl ResourceCatalog {
    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &DirectoryQuery,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        proof.manage(Permission::ResourceRead)?;
        crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            audit,
            (self, proof, q, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, q, audit) = *ctx;
                    p.manage(Permission::ResourceRead)?;
                    let mut items = checked_input(s.resources.directory_in(tx, q).await?)?;
                    let more = items.len() > q.limit;
                    items.truncate(q.limit);
                    let next = if more {
                        items.last().map(|v| v["id"].clone())
                    } else {
                        None
                    };
                    p.check_live()?;
                    s.audit_store
                        .append_request_in(tx, audit, 200, "success")
                        .await?;
                    Ok(json!({"items":items,"nextCursor":next}))
                })
            },
            crate::transaction::TransactionOwner::ResourceCatalog,
        )
        .await
    }
}
