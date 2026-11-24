//! Ordered bounded scans reuse the checked SQL predicate for both pages and totals.
//! ref: sqlx sqlx-core/src/query_builder.rs — bound arrays, never interpolated input.
use super::*;

use rss_mdm_query::directory::Position;
use sources::Scope;
use sqlx::Row;
const BATCH: usize = 1000;
pub(super) fn metadata(name: &str) -> bool {
    !name.starts_with("authorization.") && !name.starts_with("reauthorization.")
}
pub(super) fn classified(q: &Query) -> bool {
    q.schema()
        .fields()
        .iter()
        .any(|f| !metadata(&f.name) && q.mentions(&f.name))
}
struct Scan<'a> {
    scope: Scope<'a>,
    query: &'a Query,
    after: Option<Position>,
    remaining: usize,
    limit: usize,
    stage: &'static str,
    exhausted: bool,
}

impl<'a> Scan<'a> {
    fn new(
        p: &AuthorizedPrincipal, grant: &Grant, query: &'a Query, after: Option<Position>,
        limit: usize, stage: &'static str,
    ) -> Result<Self, Error> {
        let devices = grant.devices_for(p, Permission::OperationRead)?
            .map(|ids| ids.into_iter().map(|id| id.into_uuid()).collect());
        let scope = Scope::new(p.tenant_id().to_owned(), devices, query);
        Ok(Self {scope, query, after, remaining: limit, limit, stage, exhausted: false})
    }

    async fn next(&mut self, c: &mut sqlx::PgConnection, requested: usize) -> Result<Vec<Value>, Error> {
        if self.exhausted { return Ok(Vec::new()); }
        // At the boundary, the next query may only distinguish exhaustion from overflow.
        let size = requested.min(self.remaining.max(1));
        let mut sql = sqlx::QueryBuilder::new("");
        self.scope.page(&mut sql, self.after.as_ref(), size)?;
        let rows = sql.build().fetch_all(c).await.map_err(super::sql)?;
        rss_mdm_query_postgres::observe_rows("operations.candidates", &rows).map_err(super::sql)?;
        check_budget(self.limit - self.remaining + rows.len(), self.limit, self.stage)?;
        self.remaining -= rows.len();
        self.exhausted = rows.len() < size;
        let mut output = Vec::with_capacity(rows.len());
        for row in rows {
            if row.try_get::<bool,_>("ambiguous").map_err(super::sql)? {
                return Err(Error::Unavailable(Failure::CommandInvariant));
            }
            output.push(row.try_get("document").map_err(super::sql)?);
        }
        if let Some(last) = output.last() {
            self.after = Some(self.query.position(last).map_err(query_error)?);
        }
        Ok(output)
    }
}

fn check_budget(rows: usize, limit: usize, stage: &'static str) -> Result<(), Error> {
    // The narrow ownership probe works on 16-byte UUIDs.
    if rss_mdm_query_postgres::within_budget(stage, rows as u64, rows as u64 * 16, limit as u64, limit as u64 * 16) {
        Ok(())
    } else { Err(Error::Unavailable(Failure::Capacity)) }
}

pub(super) fn id(row: &Value) -> Result<Uuid, Error> {
    row["id"].as_str().and_then(|s| Uuid::parse_str(s).ok()).ok_or(Error::Unavailable(Failure::CommandInvariant))
}

async fn classify(
    s: &Operations,
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    grant: &Grant,
    rows: &mut [Value],
    now: i64,
) -> Result<(), Error> {
    let mut decisions = s.decisions(c, p, grant, rows, now).await?;
    for row in rows {
        let id = id(row)?;
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
    sql.push_bind(Value::Array(rows)).push("::jsonb)), classified AS(SELECT document,(document->>'id')::uuid AS id,document->>'kind' AS kind,(document->>'device')::uuid AS device,(document->>'policy')::uuid AS policy,document->>'origin' AS source_kind,(document->>'deadline')::bigint AS deadline,document->>'status' AS status,document->'authorization' AS authorization_summary,document->'reauthorization' AS reauthorization_summary FROM batch) SELECT document FROM classified WHERE true");
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
    let sizes = rows[start..].iter().take(BATCH).map(|row|
        row["inputBytes"].as_i64().ok_or(Error::Unavailable(Failure::CommandInvariant)));
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
) -> Result<rss_mdm_query::Page<Value>, Error> {
    let (p, grant) = authority;
    let after = q.after(codec, binding).map_err(query_error)?;
    let mut scan = Scan::new(p, grant, q, after, s.budgets.page, "operations.sources")?;
    let filtering = classified(q);
    let mut items = Vec::new();
    while items.len() <= q.limit() {
        let size = if filtering { BATCH } else { q.limit() + 1 - items.len() };
        let rows = scan.next(c, size).await?;
        if rows.is_empty() { break; }
        if filtering {
            let mut start = 0;
            while start < rows.len() && items.len() <= q.limit() {
                let end = split(&rows, start)?;
                let mut batch = rows[start..end].to_vec();
                classify(s,c,p,grant,&mut batch,as_of).await?;
                items.extend(matching(c,q,batch).await?);
                start = end;
            }
        } else { items.extend(rows); }
    }
    let mut page = q.unprojected_page(items,codec,binding).map_err(query_error)?;
    if !filtering && (q.selects("authorization") || q.selects("reauthorization")) {
        enrich(s,c,p,grant,&mut page.items,as_of).await?;
    }
    Ok(page)
}

pub(super) async fn statistics(
    s: &Operations,
    c: &mut sqlx::PgConnection,
    p: &AuthorizedPrincipal,
    grant: &Grant,
    q: &Query,
    now: i64,
) -> Result<rss_mdm_query::Statistics<Statistics>, Error> {
    let stage = "operations.statistics.sources";
    let mut scan = Scan::new(p, grant, q, None, s.budgets.statistics, stage)?;
    let statistics = if !classified(q) {
        let mut sql = sqlx::QueryBuilder::new("");
        scan.scope.totals(&mut sql,s.budgets.statistics)?;
        let (total, commands, runs, unknown, ambiguous): (i64,i64,i64,i64,bool) =
            sql.build_query_as().fetch_one(c).await.map_err(super::sql)?;
        check_budget(total as usize, s.budgets.statistics, stage)?;
        if ambiguous { return Err(Error::Unavailable(Failure::CommandInvariant)); }
        Statistics { total:total as u64, commands:commands as u64, action_runs:runs as u64, unknown:unknown as u64 }
    } else {
        let mut counts = Statistics {total:0,commands:0,action_runs:0,unknown:0};
        loop {
            let rows = scan.next(c,BATCH).await?;
            if rows.is_empty() { break; }
            let mut start = 0;
            while start < rows.len() {
                let end = split(&rows,start)?;
                let mut batch = rows[start..end].to_vec();
                classify(s,c,p,grant,&mut batch,now).await?;
                for row in matching(c,q,batch).await? {
                    counts.total += 1;
                    if row["kind"] == "command" { counts.commands += 1 } else { counts.action_runs += 1 }
                    if row["status"] == "unknown" { counts.unknown += 1 }
                }
                start = end;
            }
        }
        counts
    };
    Ok(rss_mdm_query::Statistics {statistics, as_of:now})
}

fn input_prefix(sizes: impl IntoIterator<Item = Result<i64, Error>>) -> Result<usize, Error> {
    let mut total = 0i64;
    let mut count = 0;
    for size in sizes {
        let size = size?;
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
