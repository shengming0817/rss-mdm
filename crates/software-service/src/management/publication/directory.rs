use super::service::{PublicationDirectory, failure, view};
use crate::management::{Error, query_error, transaction};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_query::directory::{Query, Schema};
use serde_json::{Value, json};
pub static PUBLICATIONS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<super::wire::PublicationSummary>("publications", &["id"], 20, 100, &[])
        .and_then(|s| {
            s.with_selectors::<OperationSelector>(
                "Original operations whose receipt references this publication",
            )
        })
        .expect("Public directory model")
});
pub static TARGETS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<crate::publication::PublicTarget>(
        "publication_targets",
        &["id"],
        20,
        100,
        &[],
    )
    .expect("Public directory model")
});
pub async fn list(
    s: &PublicationDirectory,
    _authorization: &rss_mdm_authorization_service::Store,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: Query,
) -> Result<
    rss_mdm_query::Page<rss_mdm_query::directory::Projection<super::wire::PublicationSummary>>,
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
  let mut sql=sqlx::QueryBuilder::new("SELECT s.record,convert_from(s.document,'UTF8')::jsonb->>'target',s.resource,s.version,a.directory FROM mdm_software_composition.subjects s JOIN mdm_software_release.aggregates a ON(a.tenant_id,a.id)=(s.tenant_id,s.record) LEFT JOIN mdm_software_composition.withdrawals w ON(w.tenant_id,w.id)=(a.tenant_id,a.directory->>'withdrawalKey') LEFT JOIN mdm_software_composition.targets t ON(t.tenant_id,t.id)=(w.tenant_id,w.id) WHERE s.tenant_id=");sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
  rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),&*PUBLICATION_BINDINGS).map_err(query_error)?;
  let rows:Vec<(String,String,String,String,Value)>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_as().fetch_all(c).await})).await?;
  let mut items=Vec::new();for(id,target,resource,version,projection)in rows{
   let service=s.services.get(&target).ok_or(Error::Publication(super::error::PublicationError::MissingSource))?;
   let key=rss_mdm_software_release::PublicationKey::new(s.tenant,&id).map_err(|_|Error::Malformed)?;
   let(record,withdrawal)=service.record_status_in(tx,&key).await?.map_err(failure)?;
   if !rss_mdm_software_release_postgres::directory_matches(&record,&projection) { return Err(Error::Unavailable(crate::management::Failure::SoftwareCatalogStorage).into()); }
   items.push(view(id,(target,resource,version),&record,withdrawal,None)?.summary);
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
                rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*TARGET_BINDINGS)
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

#[derive(schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct OperationSelector {
    operation_id: Vec<uuid::Uuid>,
}

pub static PUBLICATION_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(&PUBLICATIONS, &[rss_mdm_query_postgres::Source::json("id", "a.directory->'id'"),
rss_mdm_query_postgres::Source::json("revision", "a.directory->'revision'"),
rss_mdm_query_postgres::Source::json("target", "a.directory->'target'"),
rss_mdm_query_postgres::Source::json("publication", "a.directory->'publication'"),
rss_mdm_query_postgres::Source::json("contentDigest", "a.directory->'contentDigest'"),
rss_mdm_query_postgres::Source::json("manifestDigest", "a.directory->'manifestDigest'"),
rss_mdm_query_postgres::Source::json("targetDigest", "a.directory->'targetDigest'"),
rss_mdm_query_postgres::Source::json("attempt", "a.directory->'attempt'"),
rss_mdm_query_postgres::Source::json("outcome", "a.directory->'outcome'"),
rss_mdm_query_postgres::Source::column("resource", "s.resource COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("version", "s.version COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("withdrawn", "((a.directory->>'withdrawn')::boolean OR w.id IS NOT NULL)"),
rss_mdm_query_postgres::Source::column("withdrawal", "(CASE WHEN w.id IS NULL THEN NULL WHEN w.complete THEN 'withdrawn' WHEN a.directory->>'outcome'='published' THEN CASE WHEN t.id IS NULL OR NOT t.attempted THEN 'preflight_retryable' ELSE 'unknown' END WHEN a.directory->>'outcome'='not_applied' THEN 'not_published' ELSE 'waiting_publication' END) COLLATE \"C\""),
rss_mdm_query_postgres::Source::column("operationId", "ARRAY(SELECT o.id::text FROM mdm_publication.operations o WHERE o.tenant_id=s.tenant_id AND o.response->>'record'=s.record)")]).expect("Complete public model storage binding")
    });

pub static TARGET_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &TARGETS,
            &[rss_mdm_query_postgres::Source::json("", "value")],
        )
        .expect("Complete public model storage binding")
    });
