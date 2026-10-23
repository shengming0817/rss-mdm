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
