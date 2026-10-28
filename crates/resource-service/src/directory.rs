use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::Page;
use rss_mdm_resource::directory::{Position, Query};
impl ResourceCatalog {
    pub async fn blueprints(
        &self,
        proof: &AuthorizedPrincipal,
        _audit: &RequestAudit,
    ) -> std::result::Result<Blueprints, Error> {
        proof.manage(Permission::ResourceRead)?;

        proof.check_live()?;
        Ok(Blueprints {
            categories: r::blueprints::CATEGORIES,
            items: r::blueprints::catalog(),
        })
    }

    pub async fn directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<
        Page<rss_mdm_query::directory::Projection<rss_mdm_resource::directory::Record>>,
        Error,
    > {
        proof.manage(Permission::ResourceRead)?;
        if proof.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, q, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, q, _audit) = *ctx;
                    let current = crate::transaction::current(tx, p).await?;
                    current.require(p, Permission::ResourceRead, None)?;
                    let binding = q
                        .binding(p.tenant_id(), p.instance_id(), &current.query_binding(p)?)
                        .map_err(query_error)?;
                    let after: Option<Position> = q
                        .cursor()
                        .map(|token| s.directory_cursor.decode(token, &binding))
                        .transpose()
                        .map_err(query_error)?;
                    if let Some(position) = &after {
                        q.validate_position(position).map_err(query_error)?;
                    }
                    let mut items =
                        checked_input(s.resources.directory_in(tx, q, after.as_ref()).await?)?;
                    let more = items.len() > q.limit();
                    items.truncate(q.limit());
                    let next = if more {
                        items
                            .last()
                            .map(|row| {
                                s.directory_cursor
                                    .encode(&binding, &q.position(row))
                                    .map(|token| token.as_str().to_owned())
                            })
                            .transpose()
                            .map_err(query_error)?
                    } else {
                        None
                    };
                    p.check_live()?;

                    Ok(Page {
                        items: items
                            .into_iter()
                            .map(|row| q.project(row))
                            .collect::<std::result::Result<_, _>>()
                            .map_err(query_error)?,
                        next_cursor: next,
                    })
                })
            },
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

#[derive(schemars::JsonSchema, serde::Serialize)]
pub struct Blueprints {
    pub categories: [&'static str; 6],
    pub items: Vec<r::blueprints::Blueprint>,
}
