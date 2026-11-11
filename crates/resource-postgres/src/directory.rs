//! Checked Resource headers; all predicates and ordering execute before the bounded SQL page.
use crate::{STORAGE, error::*, store::ResourceStore};
use futures::TryStreamExt;
use rss_mdm_query::directory::{Position, Query};
use rss_mdm_query_postgres::{Bindings, Source};
use rss_mdm_resource::directory::{Record, SCHEMA};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::{Postgres, QueryBuilder, Row};

impl ResourceStore {
    /// Query the complete tenant candidate set; returned lookahead is also integrity checked.
    pub async fn directory_in(
        &self,
        tx: &mut PgTransaction<'_>,
        q: &Query,
        after: Option<&Position>,
    ) -> InTransaction<Vec<Record>> {
        input!(self.validate_transaction(tx)?);
        if q.require_schema(schema()).is_err() {
            return Ok(Err(Rejection::InvalidInput));
        }
        let mut sql = QueryBuilder::<Postgres>::new("");
        if select(&mut sql, tx.tenant_id(), q, after).is_err() {
            return Ok(Err(Rejection::InvalidInput));
        }
        let tenant = tx.tenant_id();
        let result = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    let query = sql.build();
                    let mut rows = query.fetch(c);
                    let mut items = Vec::new();
                    while let Some(row) = rows.try_next().await? {
                        let header = match STORAGE
                            .checked(row.try_get("document")?, row.try_get("digest")?)
                        {
                            Ok(header) => header,
                            Err(error) => return Ok(Err(error)),
                        };
                        let id: String = row.try_get("id")?;
                        match crate::codec::directory_header(
                            &header,
                            tenant,
                            &id,
                            row.try_get("revision")?,
                        ) {
                            Ok(item) => {
                                let expected: serde_json::Value = row.try_get("directory")?;
                                if !crate::directory_projection::from_record(&item)
                                    .is_ok_and(|actual| actual == expected)
                                {
                                    return Ok(Err(STORAGE.fault("directory projection")));
                                }
                                items.push(item);
                            }
                            Err(error) => return Ok(Err(error)),
                        }
                    }
                    Ok(Ok(items))
                })
            })
            .await?;
        Ok(Ok(result?))
    }
}
/// Append the owner's complete SELECT, reusable for real PostgreSQL execution-plan inspection.
pub fn select(
    sql: &mut QueryBuilder<Postgres>,
    tenant: rss_request_context::TenantId,
    q: &Query,
    after: Option<&Position>,
) -> rss_mdm_query::Result<()> {
    q.require_schema(schema())?;
    sql.push("SELECT id,revision,document,digest,directory FROM mdm_resource.aggregates WHERE tenant_id=").push_bind(tenant.to_string()).push("::uuid");
    rss_mdm_query_postgres::append(sql, q, after, &*BINDINGS)
}
/// The canonical aggregate projection binds every executable public field.
pub static BINDINGS: std::sync::LazyLock<Bindings> = std::sync::LazyLock::new(|| {
    Bindings::new(
        &SCHEMA,
        &[
            Source::required_column("id", "id COLLATE \"C\""),
            Source::required_column("revision", "revision"),
            Source::json("", "directory"),
        ],
    )
    .expect("Resource directory storage binds every model field")
});
/// Return the complete, storage-checked Resource directory declaration.
pub fn schema() -> &'static rss_mdm_query::directory::Schema {
    BINDINGS.schema()
}

impl ResourceStore {
    /// Bounded version discovery from the canonical checked Resource header.
    pub async fn version_directory_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: &str,
        q: &rss_mdm_query::directory::Query,
        after: Option<&rss_mdm_query::directory::Position>,
    ) -> InTransaction<Vec<serde_json::Value>> {
        input!(self.validate_transaction(tx)?);
        if q.require_schema(&rss_mdm_resource::directory::VERSION_SCHEMA)
            .is_err()
        {
            return Ok(Err(Rejection::InvalidInput));
        }
        let tenant = tx.tenant_id();
        let id = id.to_owned();
        let key = id.clone();
        let row=tx.with_connection(move|c|Box::pin(async move{sqlx::query("SELECT id,revision,document,digest FROM mdm_resource.aggregates WHERE tenant_id=$1::uuid AND id=$2 FOR SHARE").bind(tenant.to_string()).bind(key).fetch_optional(c).await})).await?;
        let Some(row) = row else {
            return Ok(Err(Rejection::NotFound));
        };
        let bytes = STORAGE.checked(row.try_get("document")?, row.try_get("digest")?)?;
        let record = crate::codec::directory_header(&bytes, tenant, &id, row.try_get("revision")?)?;
        if record.kind != rss_mdm_resource::Kind::Software {
            return Ok(Err(Rejection::InvalidInput));
        }
        let document: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| STORAGE.fault("version directory"))?;
        let mut sql = QueryBuilder::new("SELECT row FROM (SELECT jsonb_build_object('resource',");
        sql.push_bind(id).push(",'version',v->>0,'state',CASE v->>1 WHEN '0' THEN 'frozen' WHEN '1' THEN 'active' WHEN '2' THEN 'deprecated' WHEN '3' THEN 'archived' END) row FROM jsonb_array_elements(")
            .push_bind(document).push("->5) v) versions WHERE true");
        if rss_mdm_query_postgres::append(&mut sql, q, after, &*VERSION_BINDINGS).is_err() {
            return Ok(Err(Rejection::InvalidInput));
        }
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
            })
            .await?;
        Ok(Ok(rows))
    }
}

/// Nested versions share one checked execution contract with their HTTP owner.
pub static VERSION_BINDINGS: std::sync::LazyLock<rss_mdm_query_postgres::Bindings> =
    std::sync::LazyLock::new(|| {
        rss_mdm_query_postgres::Bindings::new(
            &rss_mdm_resource::directory::VERSION_SCHEMA,
            &[
                rss_mdm_query_postgres::Source::json("resource", "row#>'{resource}'"),
                rss_mdm_query_postgres::Source::json("version", "row#>'{version}'"),
                rss_mdm_query_postgres::Source::json("state", "row#>'{state}'"),
            ],
        )
        .expect("Complete public model storage binding")
    });
