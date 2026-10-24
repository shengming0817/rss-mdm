//! Checked Resource headers; all predicates and ordering execute before the bounded SQL page.
use crate::{STORAGE, error::*, store::ResourceStore};
use futures::TryStreamExt;
use rss_mdm_query::{Expression, Operator};
use rss_mdm_resource::directory::{Field, Position, Query, Record, Scalar};
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
        input!(self.check(tx)?);
        if after.is_some_and(|p| q.validate_position(p).is_err()) {
            return Ok(Err(Rejection::InvalidInput));
        }
        let mut sql = QueryBuilder::<Postgres>::new(
            "WITH headers AS (SELECT id,revision,document,digest,convert_from(document,'UTF8')::jsonb AS header FROM mdm_resource.aggregates WHERE tenant_id=",
        );
        sql.push_bind(tx.tenant_id().to_string())
            .push("::uuid) SELECT id,revision,document,digest FROM headers WHERE ");
        if let Some(filter) = q.filter() {
            expression(&mut sql, filter);
        } else {
            sql.push("TRUE");
        }
        if let Some(position) = after {
            sql.push(" AND (");
            for (i, sort) in q.sort().iter().enumerate() {
                if i != 0 {
                    sql.push(" OR ");
                }
                sql.push("(");
                for (j, prefix) in q.sort().iter().take(i).enumerate() {
                    sql.push(column(prefix.field)).push(" = ");
                    value(&mut sql, &position.0[j]);
                    sql.push(" AND ");
                }
                sql.push(column(sort.field))
                    .push(if sort.descending { " < " } else { " > " });
                value(&mut sql, &position.0[i]);
                sql.push(")");
            }
            sql.push(")");
        }
        sql.push(" ORDER BY ");
        for (i, sort) in q.sort().iter().enumerate() {
            if i != 0 {
                sql.push(",");
            }
            sql.push(column(sort.field))
                .push(if sort.descending { " DESC" } else { " ASC" });
        }
        sql.push(" LIMIT ").push_bind((q.limit() + 1) as i64);
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
                            Ok(item) => items.push(item),
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
fn column(field: Field) -> &'static str {
    match field {
        Field::Id => "id COLLATE \"C\"",
        Field::Revision => "revision",
        Field::Kind => {
            "(CASE header->>3 WHEN '0' THEN 'software' WHEN '1' THEN 'script' WHEN '2' THEN 'configuration' WHEN '3' THEN 'native_collection' WHEN '4' THEN 'agent_collection' WHEN '5' THEN 'telemetry_profile' END) COLLATE \"C\""
        }
        Field::Active => {
            "EXISTS(SELECT 1 FROM jsonb_array_elements(header->5) AS version WHERE version->>1='1')"
        }
        _ => unreachable!("validated query excludes projection-only selectors"),
    }
}
fn value(sql: &mut QueryBuilder<Postgres>, v: &Scalar) {
    match v {
        Scalar::Text(v) => {
            sql.push_bind(v.clone());
        }
        Scalar::Integer(v) => {
            sql.push_bind(*v);
        }
        Scalar::Boolean(v) => {
            sql.push_bind(*v);
        }
    }
}
fn expression(sql: &mut QueryBuilder<Postgres>, expr: &Expression<Field, Scalar>) {
    sql.push("(");
    match expr {
        Expression::And(children) | Expression::Or(children) => {
            let separator = if matches!(expr, Expression::And(_)) {
                " AND "
            } else {
                " OR "
            };
            for (i, child) in children.iter().enumerate() {
                if i != 0 {
                    sql.push(separator);
                }
                expression(sql, child);
            }
        }
        Expression::Compare {
            field,
            operator,
            values,
        } => {
            sql.push(column(*field)).push(match operator {
                Operator::Eq => " = ",
                Operator::Ne => " <> ",
                Operator::Lt => " < ",
                Operator::Le => " <= ",
                Operator::Gt => " > ",
                Operator::Ge => " >= ",
                Operator::In => " IN ",
                Operator::Out => " NOT IN ",
                Operator::Icontains => unreachable!("Resource rejects substring predicates"),
            });
            if operator.set() {
                sql.push("(");
            }
            for (i, v) in values.iter().enumerate() {
                if i != 0 {
                    sql.push(",");
                }
                value(sql, v);
            }
            if operator.set() {
                sql.push(")");
            }
        }
    }
    sql.push(")");
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
        input!(self.check(tx)?);
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
        let mut sql = QueryBuilder::new("SELECT jsonb_build_object('resource',");
        sql.push_bind(id).push(",'version',v->>0,'state',CASE v->>1 WHEN '0' THEN 'frozen' WHEN '1' THEN 'active' WHEN '2' THEN 'deprecated' WHEN '3' THEN 'archived' END) FROM jsonb_array_elements(").push_bind(document).push("->5) v WHERE TRUE");
        fn column(name: &str) -> &'static str {
            match name {
                "version" => "(v->>0) COLLATE \"C\"",
                "state" => {
                    "(CASE v->>1 WHEN '0' THEN 'frozen' WHEN '1' THEN 'active' WHEN '2' THEN 'deprecated' WHEN '3' THEN 'archived' END) COLLATE \"C\""
                }
                _ => unreachable!("checked version field"),
            }
        }
        if rss_mdm_query_postgres::append(&mut sql, q, after, column).is_err() {
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
