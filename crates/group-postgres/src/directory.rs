//! Bounded current metadata reads, without materializing rule or member histories.
use crate::{model::*, storage, store::input};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
/// Filters and ID ordering for one tenant's Group directory.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryQuery {
    /// Exclusive ID boundary in the requested order.
    pub after: Option<uuid::Uuid>,
    /// Maximum number of returned records, from one to one thousand.
    #[serde(default = "limit")]
    pub limit: usize,
    /// Descending ID order when true; ascending otherwise.
    #[serde(default)]
    pub descending: bool,
    /// Exact kind, if selected.
    pub kind: Option<GroupKind>,
    /// Include only the selected tombstone state; current records by default.
    #[serde(default)]
    pub deleted: bool,
    /// Literal name substring; not a SQL wildcard expression.
    pub name: Option<String>,
}
fn limit() -> usize {
    64
}
impl crate::GroupStore {
    /// Read bounded Group metadata through the owning runtime and tenant transaction.
    pub async fn directory_in(
        &self,
        tx: &mut PgTransaction<'_>,
        q: &DirectoryQuery,
    ) -> InTransaction<Vec<Group>> {
        input!(self.check_transaction(tx)?);
        if !(1..=1000).contains(&q.limit)
            || q.after.is_some_and(|v| v.is_nil())
            || q.name.as_ref().is_some_and(|v| v.len() > 4096)
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let tenant = self.tenant.to_string();
        let q = q.clone();
        let kind = q.kind.map(|v| match v {
            GroupKind::Static => "static",
            GroupKind::Dynamic => "dynamic",
        });
        let rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT * FROM mdm_group.groups WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR CASE WHEN $3 THEN id<$2 ELSE id>$2 END) AND ($4::text IS NULL OR kind=$4) AND deleted=$5 AND ($6::text IS NULL OR strpos(lower(name),lower($6))>0) ORDER BY CASE WHEN NOT $3 THEN id END ASC,CASE WHEN $3 THEN id END DESC LIMIT $7")
                .bind(tenant).bind(q.after).bind(q.descending).bind(kind).bind(q.deleted).bind(q.name).bind((q.limit+1) as i64).fetch_all(c).await
        })).await?;
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
                    name: r.try_get("name")?,
                    description: r.try_get("description")?,
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
