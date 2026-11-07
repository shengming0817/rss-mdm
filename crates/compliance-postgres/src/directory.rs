use super::*;
use rss_mdm_query::directory::{Position, Query, Schema};
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<DirectoryRow<Value>>(
    "compliance_rules", &["id"], 50, 50,
    &[rss_mdm_query::directory::Exclusion { path: "definition.criteria", reason: "Recursive rule AST is not a scalar directory predicate or device-query execution request" }],
).expect("Compliance public model is fully described")
});
static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        use rss_mdm_query_postgres::{Bindings, Source};
        Bindings::new(
            &SCHEMA,
            &[
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
            ],
        )
        .expect("Compliance storage binds every public field")
    });
pub fn schema() -> &'static Schema {
    BINDINGS.schema()
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryRow<C> {
    pub id: Uuid,
    pub revision: i64,
    pub name: Option<String>,
    pub enabled: bool,
    pub deleted: bool,
    pub severity: rss_mdm_compliance::Severity,
    pub platform: rss_mdm_compliance::Platform,
    pub target_kind: TargetKind,
    pub definition: rss_mdm_compliance::Definition<C>,
}
#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    All,
    Groups,
}
pub async fn list(
    c: &mut PgConnection,
    t: TenantId,
    q: &Query,
    after: Option<&Position>,
) -> Result<Vec<Value>> {
    tenant(c, t).await?;
    q.require_schema(schema()).map_err(|_| corrupt())?;
    let mut sql = sqlx::QueryBuilder::new(
        "SELECT jsonb_build_object('id',r.id,'revision',r.revision,'name',v.definition->'presentation'->>'name','enabled',r.enabled,'deleted',r.deleted,'severity',v.definition->>'severity','platform',v.definition->>'platform','targetKind',v.definition->'target'->>'kind','definition',v.definition) FROM mdm_compliance.rules r JOIN mdm_compliance.versions v ON (v.tenant_id,v.rule_id,v.revision)=(r.tenant_id,r.id,r.revision) WHERE r.tenant_id=",
    );
    sql.push_bind(t.to_string()).push("::uuid");
    rss_mdm_query_postgres::append(&mut sql, q, after, &*BINDINGS).map_err(|_| corrupt())?;
    sql.build_query_scalar().fetch_all(c).await
}
