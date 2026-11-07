//! Domain-owned Group directory mapping; the query adapter owns only SQL syntax.
use crate::{model::*, storage, store::input};
use rss_mdm_group::{AssetContext, GroupId};
use rss_mdm_query::directory::{Position, Query, Schema};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row as _;
/// Query fields consumed by Group metadata SQL and route documentation.
pub static SCHEMA: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| {
    Schema::derived::<Row>("groups", &["id"], 64, 1000, &[])
        .and_then(|s| s.no_range("ruleVersion"))
        .expect("Group public model is fully described")
});
static BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        use rss_mdm_query_postgres::{Bindings, Source};
        Bindings::new(
            &SCHEMA,
            &[
                Source::column("id", "id::text COLLATE \"C\""),
                Source::column("kind", "kind COLLATE \"C\""),
                Source::column("systemSelector", "system_selector COLLATE \"C\""),
                Source::column("assetContext", "asset_context COLLATE \"C\""),
                Source::column("name", "(presentation->>'name') COLLATE \"C\""),
                Source::column("revision", "revision"),
                Source::column("calculationRevision", "calculation_revision"),
                Source::column("memberVersion", "member_version"),
                Source::column("memberCount", "member_count"),
                Source::column("ruleVersion", "rule_version COLLATE \"C\""),
                Source::column("deleted", "deleted"),
                Source::json("presentation", "presentation"),
            ],
        )
        .expect("Group storage binds every public field")
    });
/// Return the same storage-checked directory used by execution and HTTP descriptions.
pub fn schema() -> &'static Schema {
    BINDINGS.schema()
}
#[derive(schemars::JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
/// Public directory row before selection removes unrequested output fields.
pub struct Row {
    /// Stable object identity within the tenant.
    pub id: rss_mdm_group::GroupId,
    /// Declared business kind.
    pub kind: crate::GroupKind,
    /// Optional built-in membership selection.
    pub system_selector: Option<crate::SystemSelector>,
    /// Asset universe in which membership is evaluated.
    pub asset_context: rss_mdm_group::AssetContext,
    #[schemars(with = "crate::Presentation")]
    /// Bounded descriptive metadata, including retained extensions.
    pub presentation: serde_json::Map<String, serde_json::Value>,
    /// Human-readable name; no authorization meaning.
    pub name: Option<String>,
    /// Current compare-and-swap revision.
    pub revision: crate::Revision,
    /// Last calculation revision.
    pub calculation_revision: i64,
    /// Published membership version.
    pub member_version: i64,
    /// Published member count.
    pub member_count: usize,
    /// Optional opaque rule revision.
    pub rule_version: Option<String>,
    /// Whether the object is a retained tombstone.
    pub deleted: bool,
}
impl crate::GroupStore {
    /// Query a bounded tenant page, applying an optional reference context before paging.
    pub async fn directory_in(
        &self,
        tx: &mut PgTransaction<'_>,
        q: &Query,
        after: Option<&Position>,
        context: Option<AssetContext>,
    ) -> InTransaction<Vec<Group>> {
        input!(self.check_transaction(tx)?);
        if q.require_schema(schema()).is_err() {
            return Ok(Err(Rejection::InvalidInput));
        }
        let mut sql = sqlx::QueryBuilder::new("SELECT * FROM mdm_group.groups WHERE tenant_id=");
        sql.push_bind(self.tenant.to_string()).push("::uuid");
        if let Some(context) = context {
            sql.push(" AND asset_context=")
                .push_bind(context.as_str())
                .push(" AND NOT deleted");
        }
        if rss_mdm_query_postgres::append(&mut sql, q, after, &*BINDINGS).is_err() {
            return Ok(Err(Rejection::InvalidInput));
        }
        let rows = tx
            .with_connection(move |c| Box::pin(async move { sql.build().fetch_all(c).await }))
            .await?;
        let groups = rows
            .into_iter()
            .map(|r| {
                Ok(Group {
                    id: storage::data(GroupId::parse(
                        &r.try_get::<uuid::Uuid, _>("id")?.to_string(),
                    ))?,
                    kind: storage::data(serde_json::from_value(serde_json::json!(
                        r.try_get::<String, _>("kind")?
                    )))?,
                    system_selector: r
                        .try_get::<Option<String>, _>("system_selector")?
                        .map(|s| storage::data(serde_json::from_value(serde_json::json!(s))))
                        .transpose()?,
                    asset_context: storage::data(serde_json::from_value(serde_json::json!(
                        r.try_get::<String, _>("asset_context")?
                    )))?,
                    presentation: crate::storage::data(serde_json::from_value(
                        r.try_get("presentation")?,
                    ))?,
                    revision: storage::data(Revision::new(r.try_get("revision")?))?,
                    calculation_revision: r.try_get("calculation_revision")?,
                    member_version: r.try_get("member_version")?,
                    member_count: storage::data(usize::try_from(
                        r.try_get::<i64, _>("member_count")?,
                    ))?,
                    rule_version: r.try_get("rule_version")?,
                    deleted: r.try_get("deleted")?,
                })
            })
            .collect::<Result<Vec<_>, rss_transactional_messaging_postgres::PgError>>()?;
        Ok(Ok(groups))
    }
}
