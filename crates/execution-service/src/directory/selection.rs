//! Ordered bounded scans reuse the checked SQL predicate for both pages and totals.
//! ref: sqlx sqlx-core/src/query_builder.rs — bound arrays, never interpolated input.
use super::*;
use crate::authorization_decision::{self, Decision};
use rss_mdm_query::directory::Position;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::BTreeMap;
const INPUT_BYTES: i64 = 16 * 1024 * 1024;
const BATCH: usize = 1000;
const DOCUMENT: &str = "jsonb_build_object('id',id,'kind',kind,'device',device,'registrationId',registration,'generation',generation,'origin',source_kind,'policy',policy,'deadline',deadline,'status',status)";
fn metadata(name: &str) -> bool {
    !matches!(
        name,
        "authorization.state" | "authorization.reason" | "reauthorization.state"
    )
}
pub(super) fn classified(q: &Query) -> bool {
    [
        "authorization.state",
        "authorization.reason",
        "reauthorization.state",
    ]
    .iter()
    .any(|f| q.mentions(f))
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Continuation {
    position: Position,
    as_of: i64,
    valid_until: Option<i64>,
}

async fn boundary(
    tx: &mut PgTransaction<'_>,
    tenant: String,
    allowed: Option<Vec<String>>,
    now: i64,
    limit: i64,
) -> crate::Result<Option<i64>> {
    let mut sql = relation(tenant, allowed, limit);
    sql.push("SELECT min(deadline) FROM visible WHERE deadline>")
        .push_bind(now);
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { sql.build_query_scalar().fetch_one(c).await })
        })
        .await?)
}
async fn candidates(
    tx: &mut PgTransaction<'_>,
    tenant: String,
    allowed: Option<Vec<String>>,
    q: &Query,
    after: Option<&Position>,
    limit: i64,
    size: usize,
) -> crate::Result<Vec<Value>> {
    let mut sql = relation(tenant, allowed, limit);
    sql.push(",selected AS(SELECT * FROM visible WHERE true");
    rss_mdm_query_postgres::prefilter(&mut sql, q, column, metadata).map_err(query_error)?;
    rss_mdm_query_postgres::page_limit(&mut sql, q, after, column, size).map_err(query_error)?;
    sql.push(") SELECT b.rows AS source_rows,CASE WHEN s.id IS NOT NULL THEN ").push(DOCUMENT).push(" END AS document,CASE WHEN s.kind='command' THEN (SELECT octet_length(o.request)+octet_length(o.authority::text)+octet_length(o.input_context::text)+coalesce(octet_length(o.dispatch_failure::text),0)+1024 FROM mdm_commands.operations o WHERE o.tenant_id=$1::uuid AND o.id=s.id) ELSE 0 END::bigint AS input_bytes FROM source_budget b LEFT JOIN selected s ON true");
    rss_mdm_query_postgres::order(&mut sql, q, column);
    let rows = tx
        .with_connection(move |c| Box::pin(async move { sql.build().fetch_all(c).await }))
        .await?;
    rss_mdm_query_postgres::observe_rows("operations.candidates", &rows)?;
    check_sources(
        rows.first()
            .ok_or(Error::Conflict)?
            .try_get("source_rows")?,
        limit,
        "operations.sources",
    )?;
    let mut output = Vec::new();
    for row in rows {
        if let Some(mut value) = row.try_get::<Option<Value>, _>("document")? {
            value["inputBytes"] = json!(
                row.try_get::<Option<i64>, _>("input_bytes")?
                    .ok_or(Error::Unavailable(Failure::CommandInvariant))?
            );
            output.push(value);
        }
    }
    Ok(output)
}
async fn classify(
    s: &crate::queries::Queries,
    tx: &mut PgTransaction<'_>,
    p: &AuthorizedPrincipal,
    grant: &authorization::Snapshot,
    rows: &mut [Value],
    now: i64,
) -> crate::Result<()> {
    let ids = rows
        .iter()
        .filter(|v| v["kind"] == "command")
        .map(|v| {
            Uuid::parse_str(v["id"].as_str().ok_or(Error::Malformed)?).map_err(|_| Error::Malformed)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let operations = storage::load_many(tx, &s.protection, ids).await?;
    let statuses = rows
        .iter()
        .filter(|v| v["kind"] == "command")
        .map(|v| {
            Ok((
                Uuid::parse_str(v["id"].as_str().ok_or(Error::Malformed)?)
                    .map_err(|_| Error::Malformed)?,
                dc::Status::restore(v["status"].as_str().ok_or(Error::Malformed)?)
                    .map_err(|_| Error::Malformed)?,
            ))
        })
        .collect::<crate::Result<BTreeMap<_, _>>>()?;
    let mut decisions =
        authorization_decision::batch(s, tx, p, grant, &operations, &statuses, now).await?;
    for row in rows {
        let id = Uuid::parse_str(row["id"].as_str().ok_or(Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        let decision = if row["kind"] == "command" {
            decisions.remove(&id).ok_or(Error::Conflict)?
        } else {
            Decision::not_applicable()
        };
        row["authorization"] =
            serde_json::to_value(decision.authorization).map_err(|_| Error::Malformed)?;
        row["reauthorization"] =
            serde_json::to_value(decision.reauthorization).map_err(|_| Error::Malformed)?;
    }
    Ok(())
}
/// Re-evaluate the full original AST, including mixed OR, on one bounded classified batch.
async fn matching(
    tx: &mut PgTransaction<'_>,
    q: &Query,
    rows: Vec<Value>,
) -> crate::Result<Vec<Value>> {
    let mut sql = sqlx::QueryBuilder::new(
        "WITH batch AS(SELECT value AS document FROM jsonb_array_elements(",
    );
    sql.push_bind(Value::Array(rows)).push("::jsonb)), classified AS(SELECT document,(document->>'id')::uuid AS id,document->>'kind' AS kind,document->>'device' AS device,(document->>'policy')::uuid AS policy,(document->>'registrationId')::uuid AS registration,(document->>'generation')::bigint AS generation,document->>'origin' AS source_kind,(document->>'deadline')::bigint AS deadline,document->>'status' AS status,document->'authorization' AS authorization,document->'reauthorization' AS reauthorization FROM batch) SELECT document FROM classified WHERE true");
    rss_mdm_query_postgres::filter(&mut sql, q, column).map_err(query_error)?;
    rss_mdm_query_postgres::order(&mut sql, q, column);
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
        })
        .await?)
}
fn split(rows: &[Value], start: usize) -> crate::Result<usize> {
    let mut bytes = 0;
    let mut end = start;
    for row in &rows[start..] {
        let size = row["inputBytes"].as_i64().ok_or(Error::Malformed)?;
        if size > INPUT_BYTES || size < 0 {
            return Err(Error::Unavailable(Failure::Capacity).into());
        }
        if bytes + size > INPUT_BYTES {
            break;
        }
        bytes += size;
        end += 1;
    }
    Ok(end)
}
async fn enrich(
    s: &crate::queries::Queries,
    tx: &mut PgTransaction<'_>,
    p: &AuthorizedPrincipal,
    grant: &authorization::Snapshot,
    rows: &mut [Value],
    now: i64,
) -> crate::Result<()> {
    let mut start = 0;
    while start < rows.len() {
        let end = split(rows, start)?;
        classify(s, tx, p, grant, &mut rows[start..end], now).await?;
        start = end;
    }
    Ok(())
}
pub(super) async fn page(
    s: &crate::queries::Queries,
    tx: &mut PgTransaction<'_>,
    p: &AuthorizedPrincipal,
    grant: &authorization::Snapshot,
    q: &Query,
    codec: &CursorCodec,
    binding: &str,
    allowed: Option<Vec<String>>,
) -> crate::Result<crate::queries::records::Page<Value, String>> {
    let now = storage::now(tx).await?;
    let token = q
        .cursor()
        .map(|token| {
            codec
                .decode::<Continuation>(token, binding)
                .map_err(query_error)
        })
        .transpose()?;
    if let Some(token) = &token {
        q.validate_position(&token.position).map_err(query_error)?;
        if token.valid_until.is_some_and(|until| now >= until) {
            return Err(Error::Conflict.into());
        }
    }
    let as_of = token.as_ref().map_or(now, |t| t.as_of);
    let until = match &token {
        Some(t) => t.valid_until,
        None => {
            boundary(
                tx,
                p.tenant_id().to_owned(),
                allowed.clone(),
                as_of,
                PAGE_SOURCES,
            )
            .await?
        }
    };
    let mut after = token.map(|t| t.position);
    let filtering = classified(q);
    let mut items = Vec::new();
    loop {
        let rows = candidates(
            tx,
            p.tenant_id().to_owned(),
            allowed.clone(),
            q,
            after.as_ref(),
            PAGE_SOURCES,
            if filtering { BATCH } else { q.limit() + 1 },
        )
        .await?;
        if rows.is_empty() {
            break;
        }
        after = rows
            .last()
            .map(|r| q.position(r))
            .transpose()
            .map_err(query_error)?;
        if filtering {
            let mut start = 0;
            while start < rows.len() {
                let end = split(&rows, start)?;
                let mut batch = rows[start..end].to_vec();
                classify(s, tx, p, grant, &mut batch, as_of).await?;
                items.extend(matching(tx, q, batch).await?);
                start = end;
                if items.len() > q.limit() {
                    break;
                }
            }
        } else {
            items.extend(rows)
        }
        if !filtering || items.len() > q.limit() {
            break;
        }
    }
    let more = items.len() > q.limit();
    items.truncate(q.limit());
    if !filtering && (q.selects("authorization") || q.selects("reauthorization")) {
        enrich(s, tx, p, grant, &mut items, as_of).await?;
    }
    if until.is_some_and(|until| until <= now) || until.is_some_and(|until| until <= as_of) {
        return Err(Error::Conflict.into());
    }
    let end_now = storage::now(tx).await?;
    if until.is_some_and(|until| end_now >= until) {
        return Err(Error::Conflict.into());
    }
    let next_cursor = if more {
        items
            .last()
            .map(|r| {
                Ok(codec
                    .encode(
                        binding,
                        &Continuation {
                            position: q.position(r)?,
                            as_of,
                            valid_until: until,
                        },
                    )?
                    .as_str()
                    .to_owned())
            })
            .transpose()
            .map_err(query_error)?
    } else {
        None
    };
    Ok(crate::queries::records::Page { items, next_cursor })
}
pub(super) async fn statistics(
    s: &crate::queries::Queries,
    tx: &mut PgTransaction<'_>,
    p: &AuthorizedPrincipal,
    grant: &authorization::Snapshot,
    q: &Query,
    allowed: Option<Vec<String>>,
) -> crate::Result<Value> {
    let now = storage::now(tx).await?;
    if !classified(q) {
        let mut sql = relation(p.tenant_id().to_owned(), allowed, STATISTICS_SOURCES);
        sql.push("SELECT b.rows,CASE WHEN b.rows<=4194304 THEN (SELECT jsonb_build_object('statistics',jsonb_build_object('total',count(*),'commands',count(*) FILTER(WHERE kind='command'),'actionRuns',count(*) FILTER(WHERE kind='action_run'),'unknown',count(*) FILTER(WHERE status='unknown')),'asOf',").push_bind(now).push(") FROM visible WHERE true");
        rss_mdm_query_postgres::filter(&mut sql, q, column).map_err(query_error)?;
        sql.push(") END FROM source_budget b");
        let (count, value): (i64, Option<Value>) = tx
            .with_connection(move |c| {
                Box::pin(async move { sql.build_query_as().fetch_one(c).await })
            })
            .await?;
        check_sources(count, STATISTICS_SOURCES, "operations.statistics.sources")?;
        return Ok(value.ok_or(Error::Conflict)?);
    }
    let until = boundary(
        tx,
        p.tenant_id().to_owned(),
        allowed.clone(),
        now,
        STATISTICS_SOURCES,
    )
    .await?;
    let mut after = None;
    let mut total = 0u64;
    let mut commands = 0u64;
    let mut runs = 0u64;
    let mut unknown = 0u64;
    loop {
        let rows = candidates(
            tx,
            p.tenant_id().to_owned(),
            allowed.clone(),
            q,
            after.as_ref(),
            STATISTICS_SOURCES,
            BATCH,
        )
        .await?;
        if rows.is_empty() {
            break;
        }
        after = rows
            .last()
            .map(|r| q.position(r))
            .transpose()
            .map_err(query_error)?;
        let mut start = 0;
        while start < rows.len() {
            let end = split(&rows, start)?;
            let mut batch = rows[start..end].to_vec();
            classify(s, tx, p, grant, &mut batch, now).await?;
            for row in matching(tx, q, batch).await? {
                total += 1;
                if row["kind"] == "command" {
                    commands += 1
                } else {
                    runs += 1
                }
                if row["status"] == "unknown" {
                    unknown += 1
                }
            }
            start = end;
        }
    }
    if until.is_some_and(|until| until <= now) {
        return Err(Error::Conflict.into());
    }
    if let Some(until) = until {
        if storage::now(tx).await? >= until {
            return Err(Error::Conflict.into());
        }
    }
    Ok(
        json!({"statistics":{"total":total,"commands":commands,"actionRuns":runs,"unknown":unknown},"asOf":now}),
    )
}

pub(super) fn requires_authority(q: &Query) -> bool {
    classified(q) || q.selects("authorization") || q.selects("reauthorization")
}
