use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::Page;
use rss_mdm_resource::directory::{Position, Query};
impl ResourceCatalog {
    pub async fn blueprints(
        &self,
        proof: &AuthorizedPrincipal,
        audit: &RequestAudit,
    ) -> std::result::Result<Value, Error> {
        proof.manage(Permission::ResourceRead)?;
        audit.require_request_settlement();
        proof.check_live()?;
        Ok(json!({"categories":r::blueprints::CATEGORIES,"items":r::blueprints::catalog()}))
    }

    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<Page<serde_json::Map<String, Value>>, Error> {
        proof.manage(Permission::ResourceRead)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let binding = q
            .binding(
                proof.tenant_id(),
                proof.instance_id(),
                &proof.authorization()?.query_binding(proof)?,
            )
            .map_err(query_error)?;
        let after: Option<Position> = q
            .cursor()
            .map(|token| self.directory_cursor.decode(token, &binding))
            .transpose()
            .map_err(query_error)?;
        if let Some(position) = &after {
            q.validate_position(position).map_err(query_error)?;
        }
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, q, audit, &after, &binding),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, q, audit, after, binding) = *ctx;
                    p.manage(Permission::ResourceRead)?;
                    let mut items =
                        checked_input(s.resources.directory_in(tx, q, after.as_ref()).await?)?;
                    let more = items.len() > q.limit();
                    items.truncate(q.limit());
                    let next = if more {
                        items
                            .last()
                            .map(|row| {
                                s.directory_cursor
                                    .encode(binding, &q.position(row))
                                    .map(|token| token.as_str().to_owned())
                            })
                            .transpose()
                            .map_err(query_error)?
                    } else {
                        None
                    };
                    p.check_live()?;
                    audit.require_request_settlement();
                    Ok(Page {
                        items: items.into_iter().map(|row| q.project(row)).collect(),
                        next_cursor: next,
                    })
                })
            },
            crate::transaction::TransactionOwner::ResourceCatalog,
        )
        .await
    }
}

fn query_error(error: rss_mdm_query::Error) -> Error {
    match error {
        rss_mdm_query::Error::CursorInvalidated => Error::ResourceCursorInvalidated,
        _ => Error::Malformed,
    }
}
