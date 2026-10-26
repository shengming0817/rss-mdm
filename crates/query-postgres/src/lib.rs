//! Product-only predicate/seek adapter. Owns no connection, table, repository or authorization.
//! ref: sqlx sqlx-core/src/query_builder.rs@v0.9.0 (bind parameters).
use rss_mdm_query::{
    Error, Expression, Operator, Result,
    directory::{Position, Query},
};
use serde_json::Value;
use sqlx::{Postgres, QueryBuilder};
/// The domain provides trusted SQL expressions. User strings never become SQL fragments.
pub type Columns = fn(&str) -> &'static str;
fn value(sql: &mut QueryBuilder<Postgres>, v: &Value) -> Result<()> {
    match v {
        Value::String(v) => {
            sql.push_bind(v.clone());
        }
        Value::Bool(v) => {
            sql.push_bind(*v);
        }
        Value::Number(v) => {
            sql.push_bind(v.as_i64().ok_or(Error::Invalid)?);
        }
        _ => return Err(Error::Invalid),
    }
    Ok(())
}
pub fn filter(sql: &mut QueryBuilder<Postgres>, q: &Query, columns: Columns) -> Result<()> {
    if let Some(e) = q.filter() {
        sql.push(" AND ");
        expression(sql, e, q.schema(), columns, |_| true)?;
    }
    Ok(())
}
/// Necessary SQL predicate for a query with fields evaluated by its domain later.
/// Replacing a whole unavailable atom with TRUE preserves AND/OR superset semantics.
/// The caller must apply the original filter after supplying those fields.
pub fn prefilter(
    sql: &mut QueryBuilder<Postgres>,
    q: &Query,
    columns: Columns,
    available: fn(&str) -> bool,
) -> Result<()> {
    if let Some(e) = q.filter() {
        sql.push(" AND ");
        expression(sql, e, q.schema(), columns, available)?;
    }
    Ok(())
}
fn expression(
    sql: &mut QueryBuilder<Postgres>,
    e: &Expression<String, Value>,
    schema: &rss_mdm_query::directory::Schema,
    columns: Columns,
    available: fn(&str) -> bool,
) -> Result<()> {
    if let Expression::Compare { field, .. } = e
        && !available(field)
    {
        sql.push("TRUE");
        return Ok(());
    }
    sql.push("(");
    match e {
        Expression::And(v) | Expression::Or(v) => {
            for (i, child) in v.iter().enumerate() {
                if i > 0 {
                    sql.push(if matches!(e, Expression::And(_)) {
                        " AND "
                    } else {
                        " OR "
                    });
                }
                expression(sql, child, schema, columns, available)?;
            }
        }
        Expression::Compare {
            field,
            operator,
            values,
        } if matches!(
            schema.field(field)?.kind,
            rss_mdm_query::directory::Kind::EnumSet(_) | rss_mdm_query::directory::Kind::UuidSet
        ) =>
        {
            if matches!(operator, Operator::Ne | Operator::Out) {
                sql.push("NOT (");
            } else {
                sql.push("(");
            }
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    sql.push(" OR ");
                }
                value(sql, v)?;
                sql.push(" = ANY(").push(columns(field)).push(")");
            }
            sql.push(")");
        }
        Expression::Compare {
            field,
            operator: Operator::Icontains,
            values,
        } => {
            sql.push("strpos(lower(")
                .push(columns(field))
                .push("),lower(");
            value(sql, &values[0])?;
            sql.push("))>0");
        }
        Expression::Compare {
            field,
            operator,
            values,
        } => {
            sql.push(columns(field)).push(match operator {
                Operator::Eq => " = ",
                Operator::Ne => " <> ",
                Operator::Lt => " < ",
                Operator::Le => " <= ",
                Operator::Gt => " > ",
                Operator::Ge => " >= ",
                Operator::In => " IN ",
                Operator::Out => " NOT IN ",
                _ => return Err(Error::Invalid),
            });
            if operator.set() {
                sql.push("(");
            }
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    sql.push(",");
                }
                value(sql, v)?;
            }
            if operator.set() {
                sql.push(")");
            }
        }
    }
    sql.push(")");
    Ok(())
}
/// Append NULLS LAST keyset continuation, stable ordering and bounded lookahead.
pub fn page(
    sql: &mut QueryBuilder<Postgres>,
    q: &Query,
    after: Option<&Position>,
    columns: Columns,
) -> Result<()> {
    page_limit(sql, q, after, columns, q.limit() + 1)
}
/// Domain scans may read several bounded batches for one public page.
pub fn page_limit(
    sql: &mut QueryBuilder<Postgres>,
    q: &Query,
    after: Option<&Position>,
    columns: Columns,
    limit: usize,
) -> Result<()> {
    let maximum = usize::from(q.schema().max_limit) + 1;
    if !(1..=maximum).contains(&limit) {
        return Err(Error::Budget);
    }
    if let Some(p) = after {
        q.validate_position(p)?;
        sql.push(" AND (");
        for (i, sort) in q.sort().iter().enumerate() {
            if i > 0 {
                sql.push(" OR ");
            }
            sql.push("(");
            for (j, prefix) in q.sort().iter().take(i).enumerate() {
                sql.push(columns(&prefix.field));
                if p.0[j].is_null() {
                    sql.push(" IS NULL");
                } else {
                    sql.push(" IS NOT DISTINCT FROM ");
                    value(sql, &p.0[j])?;
                }
                sql.push(" AND ");
            }
            if p.0[i].is_null() {
                sql.push("FALSE");
            } else {
                sql.push("(")
                    .push(columns(&sort.field))
                    .push(if sort.descending { " < " } else { " > " });
                value(sql, &p.0[i])?;
                sql.push(" OR ")
                    .push(columns(&sort.field))
                    .push(" IS NULL)");
            }
            sql.push(")");
        }
        sql.push(")");
    }
    order(sql, q, columns);
    sql.push(" LIMIT ").push_bind(limit as i64);
    Ok(())
}
/// Preserve the same ordering outside a bounded candidate subquery.
pub fn order(sql: &mut QueryBuilder<Postgres>, q: &Query, columns: Columns) {
    sql.push(" ORDER BY ");
    for (i, sort) in q.sort().iter().enumerate() {
        if i > 0 {
            sql.push(",");
        }
        sql.push(columns(&sort.field)).push(if sort.descending {
            " DESC NULLS LAST"
        } else {
            " ASC NULLS LAST"
        });
    }
}
pub fn append(
    sql: &mut QueryBuilder<Postgres>,
    q: &Query,
    after: Option<&Position>,
    columns: Columns,
) -> Result<()> {
    filter(sql, q, columns)?;
    page(sql, q, after, columns)
}

/// Observe actual PostgreSQL cell payloads before business JSON/decryption. No values are logged.
/// This excludes wire framing; SQLx independently reports the executed statement and elapsed time.
pub fn observe_rows(
    stage: &'static str,
    rows: &[sqlx::postgres::PgRow],
) -> std::result::Result<usize, sqlx::Error> {
    use sqlx::{Row, ValueRef};
    let mut bytes = 0usize;
    for row in rows {
        for column in 0..row.len() {
            let value = row.try_get_raw(column)?;
            if !value.is_null() {
                bytes = bytes
                    .checked_add(value.as_bytes().map_err(sqlx::Error::Decode)?.len())
                    .ok_or_else(|| sqlx::Error::Protocol("query byte counter overflow".into()))?;
            }
        }
    }
    tracing::debug!(target:"rss_mdm.query_read",stage,rows=rows.len(),payload_bytes=bytes,"bounded query payload");
    Ok(bytes)
}

/// Record a provider's narrow work/input measurement, without values or identities.
/// Owners choose independent limits and translate rejection to their capacity error.
pub fn within_budget(
    stage: &'static str,
    rows: u64,
    bytes: u64,
    max_rows: u64,
    max_bytes: u64,
) -> bool {
    let accepted = rows <= max_rows && bytes <= max_bytes;
    tracing::debug!(target: "rss_mdm.query_budget", stage, rows, payload_bytes=bytes, max_rows, max_bytes, accepted);
    if !accepted {
        tracing::warn!(target: "rss_mdm.query_budget", stage, rows, payload_bytes=bytes, max_rows, max_bytes, "query budget exceeded");
    }
    accepted
}
