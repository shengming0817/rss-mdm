use super::*;
use rss_mdm_query::directory::{Position, Query};
use rss_mdm_query_postgres::Source;
pub static SOURCES: &[rss_mdm_query_postgres::Source] = &[
    Source::column("id", "r.id::text COLLATE \"C\""),
    Source::column("revision", "r.revision"),
    Source::column(
        "name",
        "(v.definition->'presentation'->>'name') COLLATE \"C\"",
    ),
    Source::column("enabled", "r.enabled"),
    Source::column("deleted", "r.deleted"),
    Source::column("severity", "(v.definition->>'severity') COLLATE \"C\""),
    Source::column("platform", "(v.definition->>'platform') COLLATE \"C\""),
    Source::column(
        "targetKind",
        "(v.definition->'target'->>'kind') COLLATE \"C\"",
    ),
    Source::json("definition", "v.definition"),
];
pub async fn list(
    c: &mut PgConnection,
    t: TenantId,
    q: &Query,
    after: Option<&Position>,
    bindings: &rss_mdm_query_postgres::Bindings,
) -> Result<Vec<Value>> {
    tenant(c, t).await?;
    q.require_schema(bindings.schema()).map_err(|_| corrupt())?;
    let mut sql = sqlx::QueryBuilder::new(
        "SELECT jsonb_build_object('id',r.id,'revision',r.revision,'name',v.definition->'presentation'->>'name','enabled',r.enabled,'deleted',r.deleted,'severity',v.definition->>'severity','platform',v.definition->>'platform','targetKind',v.definition->'target'->>'kind','definition',v.definition) FROM mdm_compliance.rules r JOIN mdm_compliance.versions v ON (v.tenant_id,v.rule_id,v.revision)=(r.tenant_id,r.id,r.revision) WHERE r.tenant_id=",
    );
    sql.push_bind(t.to_string()).push("::uuid");
    rss_mdm_query_postgres::append(&mut sql, q, after, bindings).map_err(|_| corrupt())?;
    sql.build_query_scalar().fetch_all(c).await
}
