//! Domain-owned Group directory mapping; the query adapter owns only SQL syntax.
use crate::{model::*, storage, store::input};
use rss_mdm_group::{AssetContext, GroupId};
use rss_mdm_query::directory::{Position, Query};
use rss_mdm_query_postgres::Source;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row as _;
/// Trusted storage roots; every service model field must bind before execution.
pub static SOURCES: &[rss_mdm_query_postgres::Source] = &[
    Source::column("id", "id"),
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
];
impl crate::GroupStore {
    /// Query a bounded tenant page, applying an optional reference context before paging.
    pub async fn directory_in(
        &self,
        tx: &mut PgTransaction<'_>,
        q: &Query,
        after: Option<&Position>,
        context: Option<AssetContext>,
        bindings: &rss_mdm_query_postgres::Bindings,
    ) -> InTransaction<Vec<Group>> {
        input!(self.check_transaction(tx)?);
        if q.require_schema(bindings.schema()).is_err() {
            return Ok(Err(Rejection::InvalidInput));
        }
        let mut sql = sqlx::QueryBuilder::new("SELECT * FROM mdm_group.groups WHERE tenant_id=");
        sql.push_bind(self.tenant.to_string()).push("::uuid");
        if let Some(context) = context {
            sql.push(" AND asset_context=")
                .push_bind(context.as_str())
                .push(" AND NOT deleted");
        }
        if rss_mdm_query_postgres::append(&mut sql, q, after, bindings).is_err() {
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
