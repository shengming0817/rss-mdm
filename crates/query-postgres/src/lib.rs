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
        expression(sql, e, q.schema(), columns)?;
    }
    Ok(())
}
fn expression(
    sql: &mut QueryBuilder<Postgres>,
    e: &Expression<String, Value>,
    schema: &rss_mdm_query::directory::Schema,
    columns: Columns,
) -> Result<()> {
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
                expression(sql, child, schema, columns)?;
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
                Operator::Icontains => unreachable!(),
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
    sql.push(" LIMIT ").push_bind((q.limit() + 1) as i64);
    Ok(())
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
