use rss_mdm_query::directory::{Field, Kind, Schema};
pub static DIRECTORY: Schema = Schema {
    id: "user_attributes",
    keys: &["fieldId"],
    default_limit: 128,
    max_limit: 128,
    fields: &[
        Field::scalar("fieldId", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("key", Kind::Text),
        Field::scalar("displayName", Kind::Text),
        Field::scalar("sourceKind", Kind::Enum(&["identity_local", "idp"])),
        Field::scalar("provider", Kind::Uuid),
        Field::scalar(
            "valueType",
            Kind::Enum(&["string", "boolean", "number", "integer", "array", "object"]),
        ),
        Field::scalar("enabled", Kind::Boolean),
        Field::scalar("sensitive", Kind::Boolean),
        Field::scalar("required", Kind::Boolean),
        Field::scalar("visibility", Kind::Enum(&["self", "profiles_read", "both"])),
        Field::scalar("displayUse", Kind::Enum(&["profile", "summary", "hidden"])),
        Field::output("collectedAfterMicros"),
        Field::output("value"),
    ],
};

use super::*;
use self::DIRECTORY as SCHEMA;
use rss_mdm_query::directory::Query;

fn column(name: &str) -> &'static str {
    match name {
        "fieldId" => "field_id::text COLLATE \"C\"",
        "revision" => "revision",
        "key" => "(value->>'key') COLLATE \"C\"",
        "displayName" => "(value->>'displayName') COLLATE \"C\"",
        "sourceKind" => "(value->'source'->>'kind') COLLATE \"C\"",
        "provider" => "(value->'source'->>'provider') COLLATE \"C\"",
        "valueType" => "(value->>'valueType') COLLATE \"C\"",
        "enabled" => "(value->>'enabled')::boolean",
        "sensitive" => "(value->>'sensitive')::boolean",
        "required" => "(value->>'required')::boolean",
        "visibility" => "(value->>'visibility') COLLATE \"C\"",
        "displayUse" => "(value->>'displayUse') COLLATE \"C\"",
        _ => unreachable!("checked attribute field"),
    }
}
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
   rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await?;
   let current=rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await?;
   current.require(p,Permission::UserAttributeDefinitionsRead,None)?;
   let binding=q.binding(&(p.tenant_id(),p.instance_id(),current.query_binding(p)?)).map_err(error)?;
   let after=q.after(&s.cursor,&binding).map_err(error)?;
   let mut sql=sqlx::QueryBuilder::new("SELECT jsonb_build_object('fieldId',field_id,'revision',revision,'collectedAfterMicros',collected_after_micros,'value',value,'key',value->>'key','displayName',value->>'displayName','sourceKind',value->'source'->>'kind','provider',value->'source'->>'provider','valueType',value->>'valueType','enabled',value->'enabled','sensitive',value->'sensitive','required',value->'required','visibility',value->>'visibility','displayUse',value->>'displayUse') FROM mdm_user_profiles.definitions WHERE value IS NOT NULL AND tenant_id=");
   sql.push_bind(p.tenant_id().to_owned()).push("::uuid");rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(error)?;
   let rows:Vec<Value>=sql.build_query_scalar().fetch_all(c).await.map_err(database)?;
   for row in &rows{let definition:DefinitionValue=serde_json::from_value(row["value"].clone()).map_err(|_|unavailable())?;model::validate(&definition).map_err(|_|unavailable())?;}
   let rows=rows.into_iter().map(serde_json::from_value::<DefinitionRow>).collect::<Result<Vec<_>,_>>().map_err(|_|unavailable())?;
   p.check_live()?;q.page_typed(rows,&s.cursor,&binding).map_err(error)
  })).await
 })).await;
    store::settle(result, audit, false)
}
