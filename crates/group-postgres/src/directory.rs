//! Domain-owned Group directory mapping; the query adapter owns only SQL syntax.
use crate::{model::*, storage, store::input};
use rss_mdm_query::directory::{Field, Kind, Position, Query, Schema};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
/// Query fields consumed by Group metadata SQL and route documentation.
pub static SCHEMA: Schema = Schema {
    id: "groups",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("kind", Kind::Enum(&["static", "dynamic", "system"])),
        Field::scalar(
            "assetContext",
            Kind::Enum(&["endpoint", "associated_device"]),
        ),
        Field::scalar("deleted", Kind::Boolean),
        Field {
            name: "name",
            kind: Kind::Text,
            filter: true,
            sort: true,
            output: false,
        },
        Field::scalar("memberCount", Kind::Integer),
        Field::scalar("calculationRevision", Kind::Integer),
        Field::scalar("memberVersion", Kind::Integer),
        Field::output("presentation"),
        Field::output("systemSelector"),
        Field::output("ruleVersion"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "id" => "id::text COLLATE \"C\"",
        "revision" => "revision",
        "kind" => "kind COLLATE \"C\"",
        "assetContext" => "asset_context COLLATE \"C\"",
        "deleted" => "deleted",
        "name" => "(presentation->>'name') COLLATE \"C\"",
        "memberCount" => "member_count",
        "calculationRevision" => "calculation_revision",
        "memberVersion" => "member_version",
        _ => unreachable!("checked Group field"),
    }
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
        if q.require_schema(&SCHEMA).is_err() {
            return Ok(Err(Rejection::InvalidInput));
        }
        let mut sql = sqlx::QueryBuilder::new("SELECT * FROM mdm_group.groups WHERE tenant_id=");
        sql.push_bind(self.tenant.to_string()).push("::uuid");
        if let Some(context) = context {
            sql.push(" AND asset_context=")
                .push_bind(context.as_str())
                .push(" AND NOT deleted");
        }
        if rss_mdm_query_postgres::append(&mut sql, q, after, column).is_err() {
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
