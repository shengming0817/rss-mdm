use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::{cursor::CursorCodec, directory::Query};
pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    let mut q = pg::directory::SCHEMA.parse(raw)?;
    q.default_filter("deleted", "false")?;
    Ok(q)
}
impl Compliance {
    pub async fn directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        q.require_schema(&pg::directory::SCHEMA)
            .map_err(crate::query_error)?;
        p.manage(Permission::ComplianceRuleRead)?;
        audit.set_action("compliance_read");
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, p, q, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, q, audit) = *ctx;
                    let current = query_authority(tx, p).await?;
                    current.require(p, Permission::ComplianceRuleRead, None)?;
                    let binding = q
                        .binding(&(p.tenant_id(), p.instance_id(), current.query_binding(p)?))
                        .map_err(crate::query_error)?;
                    let codec = CursorCodec::from_key(s.cursor_key.clone());
                    let after = q.after(&codec, &binding).map_err(crate::query_error)?;
                    let tenant = s.tenant;
                    let query = q.clone();
                    let rows = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                pg::directory::list(c, tenant, &query, after.as_ref()).await
                            })
                        })
                        .await?;
                    for row in &rows {
                        let definition: Definition =
                            stored(serde_json::from_value(row["definition"].clone()))?;
                        stored(definition.validate())?;
                    }
                    p.check_live()?;
                    audit.require_request_settlement();
                    json(&q.page(rows, &codec, &binding).map_err(crate::query_error)?)
                })
            },
            TransactionOwner::Compliance,
        )
        .await
    }
}

pub fn schema() -> &'static rss_mdm_query::directory::Schema {
    &pg::directory::SCHEMA
}
