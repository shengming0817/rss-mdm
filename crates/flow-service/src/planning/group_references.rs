//! Fixed relationship projection; only authorized keyset rows leave PostgreSQL.
use super::*;
use rss_mdm_inventory_service::groups::references::{Kind, Page, PageRequest, Relation};
use sqlx::Row;
fn kind_rank(kind: Kind) -> i32 {
    match kind {
        Kind::Group => 0,
        Kind::Scope => 1,
        Kind::Policy => 2,
        Kind::ComplianceRule => 3,
    }
}
fn relation_rank(relation: Relation) -> i32 {
    match relation {
        Relation::Direct => 0,
        Relation::Indirect => 1,
    }
}
impl Planning {
    pub(super) async fn group_references_in(
        &self,
        tx: &mut PgTransaction<'_>,
        root: Uuid,
        request: PageRequest,
    ) -> Result<Page> {
        let tenant = self.tenant.to_string();
        let relation = match request.relation.as_str() {
            "all" => None,
            "direct" => Some(0),
            "indirect" => Some(1),
            _ => return Err(Error::Malformed.into()),
        };
        let after = request.after;
        let row = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query(include_str!("group_references.sql"))
                        .bind(tenant)
                        .bind(root)
                        .bind(request.kind.map(kind_rank))
                        .bind(relation)
                        .bind(
                            request
                                .allowed
                                .into_iter()
                                .map(kind_rank)
                                .collect::<Vec<_>>(),
                        )
                        .bind(after.map(|k| kind_rank(k.0)))
                        .bind(after.map(|k| k.1))
                        .bind(after.map(|k| relation_rank(k.2)))
                        .bind(request.limit as i64)
                        .fetch_one(c)
                        .await
                })
            })
            .await?;
        if row.try_get::<bool, _>("invalid")? {
            return Err(Error::Conflict.into());
        }
        Ok(Page {
            items: stored(serde_json::from_str(row.try_get("items")?))?,
            generation: row.try_get("generation")?,
            blocked: row.try_get("blocked")?,
        })
    }
}
