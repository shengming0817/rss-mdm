use rss_mdm_query::directory::Schema;
pub static DIRECTORY: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<DefinitionRow>("user_attributes", &["fieldId"], 128, 128, &[])
        .expect("Public directory model")
});

use self::DIRECTORY as SCHEMA;
use super::*;
use rss_mdm_query::directory::Query;

fn error(e: rss_mdm_query::Error) -> Error {
    match e {
        rss_mdm_query::Error::CursorInvalidated => Error::Conflict,
        _ => Error::Malformed,
    }
}
pub(super) async fn list(
    s: &Backend,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: &Query,
) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<DefinitionRow>>, Error> {
    q.require_schema(&SCHEMA).map_err(error)?;
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(8));
    let result=s.audit.read(s.tenant,&budget.control(),(s,p,q),|ctx,tx|Box::pin(async move{
  tx.with_connection_context(ctx,|(s,p,q),c|Box::pin(async move{
   rss_mdm_authorization_service::lock_on(rss_mdm_install_support::StorageProfile::Mdm, c,p.tenant_id(),p.instance_id()).await?;
   let current=rss_mdm_authorization_service::snapshot_on(rss_mdm_install_support::StorageProfile::Mdm, c,p.tenant_id(),p.instance_id()).await?;
   current.require(p,Permission::UserAttributeDefinitionsRead,None)?;
   let binding=q.binding(&(p.tenant_id(),p.instance_id(),current.query_binding(p)?)).map_err(error)?;
   let after=q.after(&s.cursor,&binding).map_err(error)?;
   let mut sql=sqlx::QueryBuilder::new("SELECT jsonb_build_object('fieldId',field_id,'revision',revision,'collectedAfterMicros',collected_after_micros,'value',value,'key',value->>'key','displayName',value->>'displayName','sourceKind',value->'source'->>'kind','provider',value->'source'->>'provider','valueType',value->>'valueType','enabled',value->'enabled','sensitive',value->'sensitive','required',value->'required','visibility',value->>'visibility','displayUse',value->>'displayUse') FROM mdm_user_profiles.definitions WHERE value IS NOT NULL AND tenant_id=");
   sql.push_bind(p.tenant_id().to_owned()).push("::uuid");rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),&*BINDINGS).map_err(error)?;
   let rows:Vec<Value>=sql.build_query_scalar().fetch_all(c).await.map_err(database)?;
   for row in &rows{let definition:DefinitionValue=serde_json::from_value(row["value"].clone()).map_err(|_|unavailable())?;model::validate(&definition).map_err(|_|unavailable())?;}
   let rows=rows.into_iter().map(serde_json::from_value::<DefinitionRow>).collect::<Result<Vec<_>,_>>().map_err(|_|unavailable())?;
   p.check_live()?;q.page_typed(rows,&s.cursor,&binding).map_err(error)
  })).await
 })).await;
    store::settle(result, audit, false)
}

pub static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &DIRECTORY,
            &[
                rss_mdm_query_postgres::Source::required_column("fieldId", "field_id"),
                rss_mdm_query_postgres::Source::column("revision", "revision"),
                rss_mdm_query_postgres::Source::column(
                    "collectedAfterMicros",
                    "collected_after_micros",
                ),
                rss_mdm_query_postgres::Source::json("value", "value"),
                rss_mdm_query_postgres::Source::column("key", "(value->>'key') COLLATE \"C\""),
                rss_mdm_query_postgres::Source::column(
                    "displayName",
                    "(value->>'displayName') COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column(
                    "sourceKind",
                    "(value->'source'->>'kind') COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column(
                    "provider",
                    "(value->'source'->>'provider') COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column(
                    "valueType",
                    "(value->>'valueType') COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column("enabled", "(value->>'enabled')::boolean"),
                rss_mdm_query_postgres::Source::column(
                    "sensitive",
                    "(value->>'sensitive')::boolean",
                ),
                rss_mdm_query_postgres::Source::column("required", "(value->>'required')::boolean"),
                rss_mdm_query_postgres::Source::column(
                    "visibility",
                    "(value->>'visibility') COLLATE \"C\"",
                ),
                rss_mdm_query_postgres::Source::column(
                    "displayUse",
                    "(value->>'displayUse') COLLATE \"C\"",
                ),
            ],
        )
        .expect("Complete public model storage binding")
    });
