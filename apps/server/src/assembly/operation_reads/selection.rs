//! Ordered bounded scans reuse the checked SQL predicate for both pages and totals.
//! ref: sqlx sqlx-core/src/query_builder.rs — bound arrays, never interpolated input.
use super::*;

use rss_mdm_query::directory::Position;
use serde::{Deserialize, Serialize};
use sqlx::Row;
const BATCH: usize = 1000;
const DOCUMENT: &str = "jsonb_build_object('id',id,'kind',kind,'device',device,'origin',source_kind,'policy',policy,'deadline',deadline,'status',status)";
fn metadata(name: &str) -> bool {
    !name.starts_with("authorization.") && !name.starts_with("reauthorization.")
}
pub(super) fn classified(q: &Query) -> bool {
    q.schema()
        .fields()
        .iter()
        .any(|f| !metadata(&f.name) && q.mentions(&f.name))
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Continuation {
    position: Position,
}

async fn candidates(
    c: &mut sqlx::PgConnection,
    tenant: String,
    allowed: Option<Vec<rss_mdm_agent_wire::DeviceId>>,
    q: &Query,
    after: Option<&Position>,
    bounds: (i64, usize),
    source_rows: &mut Option<i64>,
) -> Result<Vec<Value>, Error> {
    let (limit, size) = bounds;
    let mut sql = relation(tenant, allowed, limit, *source_rows);
    sql.push(",selected AS(SELECT * FROM visible WHERE true");
    rss_mdm_query_postgres::prefilter(&mut sql, q, &*BINDINGS, metadata).map_err(query_error)?;
    rss_mdm_query_postgres::page_limit(&mut sql, q, after, &*BINDINGS, size)
        .map_err(query_error)?;
    sql.push(") SELECT b.rows AS source_rows,CASE WHEN s.id IS NOT NULL THEN ").push(DOCUMENT).push(" END AS document,coalesce(s.input_bytes,0)::bigint AS input_bytes FROM source_budget b LEFT JOIN selected s ON true");
    rss_mdm_query_postgres::order(&mut sql, q, &*BINDINGS).map_err(query_error)?;
    let rows = {
        let c = &mut *c;
        sql.build().fetch_all(c).await.map_err(super::sql)
    }?;
    rss_mdm_query_postgres::observe_rows("operations.candidates", &rows).map_err(super::sql)?;
    let count = rows
        .first()
        .ok_or(Error::Conflict)?
        .try_get("source_rows")
        .map_err(super::sql)?;
    check_sources(count, limit, "operations.sources")?;
    *source_rows = Some(count);
    let mut output = Vec::new();
    for row in rows {
        if let Some(mut value) = row
            .try_get::<Option<Value>, _>("document")
            .map_err(super::sql)?
        {
            value["inputBytes"] = json!(
                row.try_get::<Option<i64>, _>("input_bytes")
                    .map_err(super::sql)?
                    .ok_or(Error::Unavailable(Failure::CommandInvariant))?
            );
            output.push(value);
        }
    }
    Ok(output)
}
async fn classify(
    s: &Operations,
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    grant: &Grant,
    rows: &mut [Value],
    now: i64,
) -> Result<(), Error> {
    let ids = rows
        .iter()
        .filter(|v| v["kind"] == "command")
        .map(|v| {
            Uuid::parse_str(v["id"].as_str().ok_or(Error::Malformed)?).map_err(|_| Error::Malformed)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut decisions = s.decisions(c, p, grant, ids, now).await?;
    for row in rows {
        let id = Uuid::parse_str(row["id"].as_str().ok_or(Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        let decision = if row["kind"] == "command" {
            decisions.remove(&id).ok_or(Error::Conflict)?
        } else {
            (Authorization::NotApplicable, Reauthorization::NotApplicable)
        };
        row["authorization"] = serde_json::to_value(decision.0).map_err(|_| Error::Malformed)?;
        row["reauthorization"] = serde_json::to_value(decision.1).map_err(|_| Error::Malformed)?;
    }
    Ok(())
}
/// Re-evaluate the full original AST, including mixed OR, on one bounded classified batch.
async fn matching(
    c: &mut sqlx::PgConnection,
    q: &Query,
    rows: Vec<Value>,
) -> Result<Vec<Value>, Error> {
    let mut sql = sqlx::QueryBuilder::new(
        "WITH batch AS(SELECT value AS document FROM jsonb_array_elements(",
    );
    sql.push_bind(Value::Array(rows)).push("::jsonb)), classified AS(SELECT document,(document->>'id')::uuid AS id,document->>'kind' AS kind,document->>'device' AS device,(document->>'policy')::uuid AS policy,document->>'origin' AS source_kind,(document->>'deadline')::bigint AS deadline,document->>'status' AS status,document->'authorization' AS authorization_summary,document->'reauthorization' AS reauthorization_summary FROM batch) SELECT document FROM classified WHERE true");
    rss_mdm_query_postgres::filter(&mut sql, q, &*BINDINGS).map_err(query_error)?;
    rss_mdm_query_postgres::order(&mut sql, q, &*BINDINGS).map_err(query_error)?;
    {
        let c = &mut *c;
        sql.build_query_scalar()
            .fetch_all(c)
            .await
            .map_err(super::sql)
    }
}
fn split(rows: &[Value], start: usize) -> Result<usize, Error> {
    let sizes = rows[start..]
        .iter()
        .map(|row| row["inputBytes"].as_i64().ok_or(Error::Malformed))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(start + input_prefix(sizes)?)
}

async fn enrich(
    s: &Operations,
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    grant: &Grant,
    rows: &mut [Value],
    now: i64,
) -> Result<(), Error> {
    let mut start = 0;
    while start < rows.len() {
        let end = split(rows, start)?;
        classify(s, c, p, grant, &mut rows[start..end], now).await?;
        start = end;
    }
    Ok(())
}
pub(super) async fn page(
    s: &Operations,
    c: &mut sqlx::PgConnection,
    authority: (&AuthorizedPrincipal, &Grant),
    q: &Query,
    codec: &CursorCodec,
    binding: &str,
    as_of: i64,
) -> Result<Page<Value>, Error> {
    let (p, grant) = authority;
    let allowed = grant
        .devices_for(p, Permission::OperationRead)?
        .map(|ids| ids.into_iter().collect::<Vec<_>>());
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
    }
    let mut after = token.map(|t| t.position);
    let filtering = classified(q);
    let mut items = Vec::new();
    let mut source_rows = None;
    loop {
        let rows = candidates(
            c,
            p.tenant_id().to_owned(),
            allowed.clone(),
            q,
            after.as_ref(),
            (PAGE_SOURCES, if filtering { BATCH } else { q.limit() + 1 }),
            &mut source_rows,
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
                classify(s, c, p, grant, &mut batch, as_of).await?;
                items.extend(matching(c, q, batch).await?);
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
        enrich(s, c, p, grant, &mut items, as_of).await?;
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
    Ok(Page { items, next_cursor })
}
pub(super) async fn statistics(
    s: &Operations,
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    grant: &Grant,
    q: &Query,
    allowed: Option<Vec<rss_mdm_agent_wire::DeviceId>>,
    now: i64,
) -> Result<Value, Error> {
    if !classified(q) {
        let mut sql = relation(p.tenant_id().to_owned(), allowed, STATISTICS_SOURCES, None);
        sql.push("SELECT b.rows,CASE WHEN b.rows<=4194304 THEN (SELECT jsonb_build_object('statistics',jsonb_build_object('total',count(*),'commands',count(*) FILTER(WHERE kind='command'),'actionRuns',count(*) FILTER(WHERE kind='action_run'),'unknown',count(*) FILTER(WHERE status='unknown')),'asOf',").push_bind(now).push(") FROM visible WHERE true");
        rss_mdm_query_postgres::filter(&mut sql, q, &*BINDINGS).map_err(query_error)?;
        sql.push(") END FROM source_budget b");
        let (count, value): (i64, Option<Value>) = {
            let c = &mut *c;
            sql.build_query_as().fetch_one(c).await.map_err(super::sql)
        }?;
        check_sources(count, STATISTICS_SOURCES, "operations.statistics.sources")?;
        return value.ok_or(Error::Conflict);
    }
    let mut after = None;
    let mut source_rows = None;
    let mut total = 0u64;
    let mut commands = 0u64;
    let mut runs = 0u64;
    let mut unknown = 0u64;
    loop {
        let rows = candidates(
            c,
            p.tenant_id().to_owned(),
            allowed.clone(),
            q,
            after.as_ref(),
            (STATISTICS_SOURCES, BATCH),
            &mut source_rows,
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
            classify(s, c, p, grant, &mut batch, now).await?;
            for row in matching(c, q, batch).await? {
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
    Ok(
        json!({"statistics":{"total":total,"commands":commands,"actionRuns":runs,"unknown":unknown},"asOf":now}),
    )
}

fn input_prefix(sizes: impl IntoIterator<Item = i64>) -> Result<usize, Error> {
    let mut total = 0i64;
    let mut count = 0;
    for size in sizes {
        if size < 0 {
            return Err(Error::Unavailable(Failure::CommandInvariant));
        }
        if total.saturating_add(size) > 16 * 1024 * 1024 {
            break;
        }
        total += size;
        count += 1;
    }
    if count == 0 {
        return Err(Error::Unavailable(Failure::Capacity));
    }
    Ok(count)
}
