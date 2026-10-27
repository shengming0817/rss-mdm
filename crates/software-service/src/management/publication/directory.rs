use super::service::{PublicationDirectory, failure, view};
use crate::management::{Error, query_error, transaction};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::directory::{Field, Kind, Query, Schema};
use serde_json::{Value, json};
pub static PUBLICATIONS: Schema = Schema {
    id: "publications",
    keys: &["id"],
    default_limit: 20,
    max_limit: 100,
    fields: &[
        Field::scalar("id", Kind::Text),
        Field::scalar("target", Kind::Text),
        Field::scalar("resource", Kind::Text),
        Field::scalar("version", Kind::Text),
        Field::filter_only("operationId", Kind::UuidSet),
        Field::output("revision"),
        Field::output("publication"),
        Field::output("contentDigest"),
        Field::output("manifestDigest"),
        Field::output("targetDigest"),
        Field::output("attempt"),
        Field::output("outcome"),
        Field::output("withdrawn"),
        Field::output("withdrawal"),
    ],
};
pub static TARGETS: Schema = Schema {
    id: "publication_targets",
    keys: &["id"],
    default_limit: 20,
    max_limit: 100,
    fields: &[
        Field::scalar("id", Kind::Text),
        Field::scalar("protocol", Kind::Enum(&["winget", "brew"])),
        Field::output("digest"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "s.record COLLATE \"C\"",
        "target" => "(convert_from(s.document,'UTF8')::jsonb->>'target') COLLATE \"C\"",
        "resource" => "s.resource COLLATE \"C\"",
        "version" => "s.version COLLATE \"C\"",
        "operationId" => {
            "ARRAY(SELECT o.id::text FROM mdm_publication.operations o WHERE o.tenant_id=s.tenant_id AND o.response->>'record'=s.record)"
        }
        _ => unreachable!("checked publication field"),
    }
}
pub async fn list(
    s: &PublicationDirectory,
    _authorization: &rss_mdm_authorization_service::Store,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: Query,
) -> Result<
    rss_mdm_query::Page<rss_mdm_query::directory::Projection<super::wire::Publication>>,
    Error,
> {
    q.require_schema(&PUBLICATIONS).map_err(query_error)?;
    p.manage(Permission::ReleaseRead)?;
    audit.set_action(
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    transaction::inspect(&s.runtime,s.tenant,(s,p,audit,q),|ctx,tx|Box::pin(async move{
  let(s,p,_audit,q)=ctx;let current=transaction::current(tx,p).await?;current.require(p,Permission::ReleaseRead,None)?;
  let binding=q.binding(&(p.tenant_id(),p.instance_id(),current.query_binding(p)?)).map_err(query_error)?;let after=q.after(&s.cursor,&binding).map_err(query_error)?;
  s.audit_store.bind_in(tx).await.map_err(Error::from)?;crate::catalog::storage::lock(tx).await.map_err(|_|Error::Conflict)?;
  let mut sql=sqlx::QueryBuilder::new("SELECT record,convert_from(document,'UTF8')::jsonb->>'target',resource,version FROM mdm_software_composition.subjects s WHERE tenant_id=");sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
  rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(query_error)?;
  let rows:Vec<(String,String,String,String)>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_as().fetch_all(c).await})).await?;
  let mut items=Vec::new();for(id,target,resource,version)in rows{
   let service=s.services.get(&target).ok_or(Error::Publication(super::error::PublicationError::MissingSource))?;
   let key=rss_mdm_software_release::PublicationKey::new(s.tenant,&id).map_err(|_|Error::Malformed)?;
   let(record,withdrawal)=service.record_status_in(tx,&key).await?.map_err(failure)?;
   items.push(view(id,(target,resource,version),&record,withdrawal,None)?);
  }
  p.check_live()?;Ok(q.page_typed(items,&s.cursor,&binding).map_err(query_error)?)
 }),transaction::TransactionOwner::Publication).await
}
pub async fn targets(
    s: &PublicationDirectory,
    _authorization: &rss_mdm_authorization_service::Store,
    p: &AuthorizedPrincipal,
    q: Query,
) -> Result<
    rss_mdm_query::Page<rss_mdm_query::directory::Projection<crate::publication::PublicTarget>>,
    Error,
> {
    q.require_schema(&TARGETS).map_err(query_error)?;
    p.manage(Permission::ReleaseRead)?;
    transaction::inspect(
        &s.runtime,
        s.tenant,
        (s, p, q),
        |ctx, tx| {
            Box::pin(async move {
                let (s, p, q) = ctx;
                let current = transaction::current(tx, p).await?;
                current.require(p, Permission::ReleaseRead, None)?;
                let rows = s.services.values().map(|s| s.target()).collect::<Vec<_>>();
                let binding = q
                    .binding(&(
                        p.tenant_id(),
                        p.instance_id(),
                        current.query_binding(p)?,
                        &rows,
                    ))
                    .map_err(query_error)?;
                let after = q.after(&s.cursor, &binding).map_err(query_error)?;
                let mut sql = sqlx::QueryBuilder::new("SELECT value FROM jsonb_array_elements(");
                sql.push_bind(json!(rows)).push(") WHERE TRUE");
                fn column(name: &str) -> &'static str {
                    match name {
                        "id" => "(value->>'id') COLLATE \"C\"",
                        "protocol" => "(value->>'protocol') COLLATE \"C\"",
                        _ => unreachable!("checked target field"),
                    }
                }
                rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), column)
                    .map_err(query_error)?;
                let rows: Vec<Value> = tx
                    .with_connection(move |c| {
                        Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
                    })
                    .await?;
                p.check_live()?;
                let rows = rows
                    .into_iter()
                    .map(crate::management::projection::<crate::publication::PublicTarget>)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(q.page_typed(rows, &s.cursor, &binding)
                    .map_err(query_error)?)
            })
        },
        transaction::TransactionOwner::Publication,
    )
    .await
}
