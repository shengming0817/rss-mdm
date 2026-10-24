use super::*;
use rss_mdm_query::directory::{Field, Kind, Position, Query, Schema};
pub static SCHEMA: Schema = Schema {
    id: "compliance_rules",
    keys: &["id"],
    default_limit: 50,
    max_limit: 50,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("name", Kind::Text),
        Field::scalar("enabled", Kind::Boolean),
        Field::scalar("deleted", Kind::Boolean),
        Field::scalar(
            "severity",
            Kind::Enum(&["low", "medium", "high", "critical"]),
        ),
        Field::scalar("platform", Kind::Enum(&["all", "windows", "macos"])),
        Field::scalar("targetKind", Kind::Enum(&["all", "groups"])),
        Field::output("definition"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "r.id::text COLLATE \"C\"",
        "revision" => "r.revision",
        "name" => "(v.definition->'presentation'->>'name') COLLATE \"C\"",
        "enabled" => "r.enabled",
        "deleted" => "r.deleted",
        "severity" => "(v.definition->>'severity') COLLATE \"C\"",
        "platform" => "(v.definition->>'platform') COLLATE \"C\"",
        "targetKind" => "(v.definition->'target'->>'kind') COLLATE \"C\"",
        _ => unreachable!("checked compliance field"),
    }
}
pub async fn list(
    c: &mut PgConnection,
    t: TenantId,
    q: &Query,
    after: Option<&Position>,
) -> Result<Vec<Value>> {
    tenant(c, t).await?;
    q.require_schema(&SCHEMA).map_err(|_| corrupt())?;
    let mut sql = sqlx::QueryBuilder::new(
        "SELECT jsonb_build_object('id',r.id,'revision',r.revision,'name',v.definition->'presentation'->>'name','enabled',r.enabled,'deleted',r.deleted,'severity',v.definition->>'severity','platform',v.definition->>'platform','targetKind',v.definition->'target'->>'kind','definition',v.definition) FROM mdm_compliance.rules r JOIN mdm_compliance.versions v ON (v.tenant_id,v.rule_id,v.revision)=(r.tenant_id,r.id,r.revision) WHERE r.tenant_id=",
    );
    sql.push_bind(t.to_string()).push("::uuid");
    rss_mdm_query_postgres::append(&mut sql, q, after, column).map_err(|_| corrupt())?;
    sql.build_query_scalar().fetch_all(c).await
}
