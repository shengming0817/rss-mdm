use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::Page;
use rss_mdm_query::directory::Query;
pub fn schema() -> &'static rss_mdm_query::directory::Schema {
    pg::directory::schema()
}
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
                        .binding(&(p.tenant_id(), p.instance_id(), current.query_binding(p)?))
                        .map_err(query_error)?;
                    q.require_schema(schema()).map_err(query_error)?;
                    let after = q
                        .after(&s.directory_cursor, &binding)
                        .map_err(query_error)?;
                    let items =
                        checked_input(s.resources.directory_in(tx, q, after.as_ref()).await?)?;
                    p.check_live()?;
                    q.page_typed(items, &s.directory_cursor, &binding)
                        .map_err(|e| query_error(e).into())
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

impl ResourceCatalog {
    /// Read the immutable original response under current authority, without replaying a write.
    pub async fn operation_receipt(
        &self,
        p: &AuthorizedPrincipal,
        id: uuid::Uuid,
    ) -> std::result::Result<Option<rss_mdm_audit_integration::operation::ReceiptSummary>, Error>
    {
        p.manage(Permission::ResourceRead)?;
        crate::transaction::inspect(&self.runtime, self.tenant, (self, p), |(_, p), tx| {
            Box::pin(async move {
                crate::transaction::current(tx, p).await?.require(
                    p,
                    Permission::ResourceRead,
                    None,
                )?;
                let raw = rss_mdm_resource_postgres::read_operation_in(
                    tx,
                    p.principal_id(),
                    p.instance_id(),
                    &id.to_string(),
                )
                .await?;
                raw.map(|v| {
                    let mut summary = rss_mdm_audit_integration::operation::ReceiptSummary::new(id);
                    match crate::wire::Response::decode(v)? {
                        crate::wire::Response::Receipt(v) => {
                            summary.object = Some(v.resource);
                            summary.revision = Some(
                                i64::try_from(v.storage_revision).map_err(|_| Error::Conflict)?,
                            );
                        }
                        crate::wire::Response::Read(v) => {
                            summary.object = Some(v.id);
                            summary.revision =
                                Some(i64::try_from(v.revision).map_err(|_| Error::Conflict)?);
                        }
                    }
                    Ok(summary)
                })
                .transpose()
            })
        })
        .await
    }
}

/// Complete Resource directory execution supplied by the Resource storage owner.
pub fn execution() -> &'static rss_mdm_query::directory::Execution { rss_mdm_resource_postgres::directory::BINDINGS.execution() }

/// Version metadata uses the Resource store's checked execution binding.
pub fn version_execution() -> &'static rss_mdm_query::directory::Execution { rss_mdm_resource_postgres::directory::VERSION_BINDINGS.execution() }
