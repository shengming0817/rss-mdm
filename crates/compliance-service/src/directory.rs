use super::*;
use crate::authorization::{Permission, context::AuthorizedPrincipal};

use rss_mdm_query::{cursor::CursorCodec, directory::Query};
pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    let mut q = schema().parse(raw)?;
    q.default_filter("deleted", "false")?;
    Ok(q)
}
impl Compliance {
    pub async fn directory(
        &self,
        p: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<
        rss_mdm_query::Page<
            rss_mdm_query::directory::Projection<
                DirectoryRow<rss_mdm_inventory_service::assets::InventoryCondition>,
            >,
        >,
        Error,
    > {
        q.require_schema(schema()).map_err(crate::query_error)?;
        p.manage(Permission::ComplianceRuleRead)?;
        audit.set_action(
            "compliance_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, p, q, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, q, _audit) = *ctx;
                    let current = query_authority(tx, p).await?;
                    current.require(p, Permission::ComplianceRuleRead, None)?;
                    let binding = q
                        .binding(&(p.tenant_id(), p.instance_id(), current.query_binding(p)?))
                        .map_err(crate::query_error)?;
                    let codec = CursorCodec::from_key(s.cursor_key.clone());
                    let after = q.after(&codec, &binding).map_err(crate::query_error)?;
                    let tenant = s.tenant;
                    let query = q.clone();
                    let rows = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                pg::directory::list(c, tenant, &query, after.as_ref(), &BINDINGS)
                                    .await
                            })
                        })
                        .await?;
                    for row in &rows {
                        let definition: Definition =
                            stored(serde_json::from_value(row["definition"].clone()))?;
                        stored(definition.validate())?;
                    }
                    p.check_live()?;

                    let rows = rows
                        .into_iter()
                        .map(|row| {
                            stored(serde_json::from_value::<
                                DirectoryRow<rss_mdm_inventory_service::assets::InventoryCondition>,
                            >(row))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Ok(q.page_typed(rows, &codec, &binding)
                        .map_err(crate::query_error)?)
                })
            },
        )
        .await
    }
}

pub fn schema() -> &'static rss_mdm_query::directory::Schema {
    BINDINGS.schema()
}

use rss_mdm_query::directory::Schema;
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<DirectoryRow<rss_mdm_inventory_service::assets::InventoryCondition>>(
    "compliance_rules", &["id"], 50, 50,
    &[rss_mdm_query::directory::Exclusion { path: "definition.criteria", reason: "Recursive rule AST is not a scalar directory predicate or device-query execution request" }],
).expect("Compliance public model is fully described")
});

#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryRow<C> {
    pub id: Uuid,
    pub revision: i64,
    #[schemars(length(min = 1, max = rss_mdm_compliance::NAME_MAX_CHARS))]
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

static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &SCHEMA,
            rss_mdm_compliance_postgres::directory::SOURCES,
        )
        .expect("Complete service model binding")
    });

/// Public model with every executable selector checked by this storage owner.
pub fn execution() -> &'static rss_mdm_query::directory::Execution {
    BINDINGS.execution()
}
