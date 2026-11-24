//! Owner projections are inlined at both consumers: independently limited directory reads
//! and exact membership checks for the selected identifiers in the same snapshot.
//! ref: PostgreSQL 17 src/backend/optimizer/plan/subselect.c (CTE inlining).
use super::super::{native_ownership::Owner as Command, task_ownership::Owner as Run};
use super::*;
use rss_mdm_install_support::StorageProfile;
use rss_mdm_query::directory::Position;
use sqlx::{Postgres, QueryBuilder};
use std::sync::LazyLock;

pub(super) enum Owner {
    Command(Command),
    Run(Run),
}

struct Source {
    relation: &'static str,
    identities: Option<&'static str>,
    command: Option<Command>,
    run: Option<Run>,
}

static COLLECTION: LazyLock<String> =
    LazyLock::new(rss_mdm_inventory_service::collection::execution::queries::relation_sql);
static SOURCES: LazyLock<[Source; 11]> = LazyLock::new(|| {
    let source = |relation, command, run| Source {
        relation,
        identities: None,
        command,
        run,
    };
    [
        source(CONFIGURATION_RELATION, Some(Command::Configuration), None),
        source(
            rss_mdm_device_service::control::directory::RELATION_SQL,
            Some(Command::Device),
            Some(Run::Device),
        ),
        source(
            rss_mdm_software_service::deployment::directory::RELATION_SQL,
            Some(Command::Software),
            Some(Run::Software),
        ),
        source(
            rss_mdm_registration_service::installation::queries::RELATION_SQL,
            Some(Command::Registration),
            None,
        ),
        source(
            rss_mdm_registration_service::enrollment::tasks::queries::RELATION_SQL,
            None,
            Some(Run::Registration),
        ),
        source(
            rss_mdm_device_access_postgres::device_access::execution::queries::RELATION_SQL,
            None,
            Some(Run::Access),
        ),
        source(
            rss_mdm_recovery_credentials::tasks::queries::RELATION_SQL,
            None,
            Some(Run::Credential(StorageProfile::Mdm)),
        ),
        source(
            rss_mdm_recovery_credentials::tasks::queries::DA_RELATION_SQL,
            None,
            Some(Run::Credential(StorageProfile::Da)),
        ),
        source(
            rss_mdm_recovery_credentials::native::queries::RELATION_SQL,
            Some(Command::Recovery),
            None,
        ),
        Source {
            identities: Some(rss_mdm_script_service::storage::IDENTITY_RELATION),
            ..source(
                rss_mdm_script_service::queries::RELATION_SQL,
                None,
                Some(Run::Script),
            )
        },
        source(&COLLECTION, None, Some(Run::Collection)),
    ]
});

pub(super) fn owner(row: &Value) -> Result<Owner, Error> {
    let source = row["source"]
        .as_u64()
        .and_then(|i| SOURCES.get(i as usize))
        .ok_or(Error::Unavailable(Failure::CommandInvariant))?;
    match row["kind"].as_str() {
        Some("command") => source.command.map(Owner::Command),
        Some("action_run") => source.run.map(Owner::Run),
        _ => None,
    }
    .ok_or(Error::Unavailable(Failure::CommandInvariant))
}

// Bound a sort that has to consume its entire input, independently of how few
// rows the client requests. A classified page reuses this one ordered window.
pub(super) const SORT_ROWS: usize = 4_096;

pub(crate) struct Scope<'a> {
    tenant: String,
    devices: Option<Vec<Uuid>>,
    query: &'a Query,
}

fn device_keys(
    expr: &rss_mdm_query::Expression<String, Value>,
) -> Option<std::collections::BTreeSet<Uuid>> {
    use rss_mdm_query::{Expression, Operator};
    match expr {
        Expression::Compare {
            field,
            operator: Operator::Eq | Operator::In,
            values,
        } if field == "device" => values
            .iter()
            .map(|v| Uuid::parse_str(v.as_str()?).ok())
            .collect(),
        Expression::And(terms) => terms.iter().filter_map(device_keys).reduce(|mut a, b| {
            a.retain(|id| b.contains(id));
            a
        }),
        Expression::Or(terms) => {
            let mut keys = std::collections::BTreeSet::new();
            for term in terms {
                keys.extend(device_keys(term)?);
            }
            Some(keys)
        }
        _ => None,
    }
}

impl<'a> Scope<'a> {
    pub(crate) fn new(tenant: String, devices: Option<Vec<Uuid>>, query: &'a Query) -> Self {
        // A positive device term is also a physical access path for a tenant-wide
        // grant. Keep the original RSQL predicate; only narrow the granted key set.
        let devices = match (devices, query.filter().and_then(device_keys)) {
            (Some(mut granted), Some(keys)) => {
                granted.retain(|id| keys.contains(id));
                Some(granted)
            }
            (None, Some(keys)) => Some(keys.into_iter().collect()),
            (granted, None) => granted,
        };
        Self {
            tenant,
            devices,
            query,
        }
    }

    fn sources(&self, sql: &mut QueryBuilder<Postgres>) {
        // Each business relation uses $1 for the transaction's tenant.
        sql.push("WITH tenant_context AS (SELECT ")
            .push_bind(self.tenant.clone())
            .push("::uuid)");
        for (i, source) in SOURCES.iter().enumerate() {
            sql.push(",owner_")
                .push(i)
                .push(" AS NOT MATERIALIZED (")
                .push(source.relation)
                .push(")");
        }
    }

    fn eligible(&self, sql: &mut QueryBuilder<Postgres>) -> Result<(), Error> {
        sql.push(" WHERE TRUE");
        if let Some(devices) = &self.devices {
            if let [device] = devices.as_slice() {
                sql.push(" AND device=").push_bind(*device);
            } else {
                sql.push(" AND device=ANY(")
                    .push_bind(devices.clone())
                    .push(")");
            }
        }
        rss_mdm_query_postgres::prefilter(sql, self.query, &*BINDINGS, selection::metadata)
            .map_err(query_error)
    }

    pub(crate) fn page(
        &self,
        sql: &mut QueryBuilder<Postgres>,
        after: Option<&Position>,
        size: usize,
    ) -> Result<(), Error> {
        self.sources(sql);
        let sorted = self.needs_sort();
        if sorted {
            self.bounded_sort(sql, after, size)?;
        } else {
            self.identity_page(sql, after, size)?;
        }
        ambiguity(sql, true);
        sql.push(" SELECT CASE WHEN selected.id IS NOT NULL THEN jsonb_build_object('id',selected.id,'kind',kind,'device',device,'origin',source_kind,'policy',policy,'deadline',deadline,'status',status,'source',source,'inputBytes',input_bytes) END AS document, ambiguous.id IS NOT NULL AS ambiguous FROM ");
        if sorted {
            sql.push("sort_work LEFT JOIN selected ON sort_work.admitted");
        } else {
            sql.push("selected");
        }
        sql.push(" LEFT JOIN ambiguous USING(id)");
        if sorted {
            sql.push(" WHERE selected.id IS NOT NULL OR NOT sort_work.admitted");
        }
        // USING merges the common id column and preserves the selected position.
        rss_mdm_query_postgres::order(sql, self.query, &*BINDINGS).map_err(query_error)
    }

    pub(super) fn needs_sort(&self) -> bool {
        if self
            .query
            .sort()
            .first()
            .is_some_and(|key| key.field != "id")
        {
            return true;
        }
        let width = if selection::classified(self.query) {
            selection::BATCH
        } else {
            self.query.limit() + 1
        };
        match &self.devices {
            // Keep the per-owner merge bounded even for a large explicit grant.
            Some(ids) => ids.len().saturating_mul(width) > SORT_ROWS,
            None => self.query.mentions("device"),
        }
    }

    fn bounded_sort(
        &self,
        sql: &mut QueryBuilder<Postgres>,
        after: Option<&Position>,
        size: usize,
    ) -> Result<(), Error> {
        sql.push(",sort_input AS MATERIALIZED (SELECT * FROM (");
        for i in 0..SOURCES.len() {
            if i > 0 {
                sql.push(" UNION ALL ");
            }
            sql.push("SELECT *,")
                .push(i)
                .push(" AS source FROM owner_")
                .push(i);
            self.eligible(sql)?;
            rss_mdm_query_postgres::seek(sql, self.query, after, &*BINDINGS)
                .map_err(query_error)?;
        }
        sql.push(") eligible LIMIT ").push_bind(SORT_ROWS as i64 + 1)
            .push("),sort_work AS MATERIALIZED (SELECT count(*)<=").push_bind(SORT_ROWS as i64)
            .push(" AS admitted FROM sort_input),selected AS MATERIALIZED (SELECT * FROM sort_input WHERE (SELECT admitted FROM sort_work)");
        rss_mdm_query_postgres::order(sql, self.query, &*BINDINGS).map_err(query_error)?;
        sql.push(" LIMIT ").push_bind(size as i64).push(")");
        Ok(())
    }

    fn identity_page(
        &self,
        sql: &mut QueryBuilder<Postgres>,
        after: Option<&Position>,
        size: usize,
    ) -> Result<(), Error> {
        let descending = self.query.sort()[0].descending;
        // IDs are non-null in every source. Natural DESC permits a backwards
        // B-tree scan; the full public ordering still applies at the merge.
        let order = if descending {
            " ORDER BY id DESC LIMIT "
        } else {
            " ORDER BY id ASC LIMIT "
        };
        let multiple = self.devices.as_deref().filter(|ids| ids.len() > 1);
        if let Some(ids) = multiple {
            sql.push(",granted AS MATERIALIZED (SELECT unnest(")
                .push_bind(ids.to_vec())
                .push("::uuid[]) AS allowed_id)");
        }
        sql.push(",selected_keys AS MATERIALIZED (SELECT * FROM (");
        for i in 0..SOURCES.len() {
            if i > 0 {
                sql.push(" UNION ALL ");
            }
            sql.push("(");
            if multiple.is_some() {
                sql.push("SELECT local_rows.* FROM granted CROSS JOIN LATERAL (");
            }
            sql.push("SELECT id,device,kind,")
                .push(i)
                .push(" AS source FROM owner_")
                .push(i);
            if multiple.is_some() {
                sql.push(" WHERE device=granted.allowed_id");
                rss_mdm_query_postgres::prefilter(sql, self.query, &*BINDINGS, selection::metadata)
                    .map_err(query_error)?;
            } else {
                self.eligible(sql)?;
            }
            // An inclusive index range skips the leading prefix while the public
            // keyset also handles other sort keys and live boundary collisions.
            if let Some(id) = after.and_then(|p| p.0.first()).and_then(Value::as_str) {
                sql.push(if descending { " AND id<=" } else { " AND id>=" })
                    .push_bind(Uuid::parse_str(id).map_err(|_| Error::QueryCursorInvalidated)?);
            }
            rss_mdm_query_postgres::seek(sql, self.query, after, &*BINDINGS)
                .map_err(query_error)?;
            sql.push(order).push_bind(size as i64);
            if multiple.is_some() {
                sql.push(") local_rows").push(order).push_bind(size as i64);
            }
            sql.push(")");
        }
        // With a unique ID the later public sort terms cannot reorder valid
        // rows. A boundary collision is checked across the full owner namespace.
        sql.push(") merged")
            .push(order)
            .push_bind(size as i64)
            .push(")");
        // Hydrating before the key limit can replace an ordered index walk with
        // a bitmap scan, a join to command status, and an unbounded sort. Look up
        // the winning coordinates in their original owner and snapshot only.
        sql.push(",selected AS MATERIALIZED (SELECT detail.*,k.source FROM selected_keys k CROSS JOIN LATERAL (");
        for i in 0..SOURCES.len() {
            if i > 0 {
                sql.push(" UNION ALL ");
            }
            sql.push("SELECT * FROM owner_")
                .push(i)
                .push(" WHERE k.source=")
                .push(i)
                .push(" AND (id,device,kind)=(k.id,k.device,k.kind)");
        }
        sql.push(" LIMIT 1) detail)");
        Ok(())
    }

    pub(crate) fn totals(
        &self,
        sql: &mut QueryBuilder<Postgres>,
        budget: usize,
    ) -> Result<(), Error> {
        self.sources(sql);
        sql.push(",selected AS MATERIALIZED (SELECT id,kind,status FROM (");
        for i in 0..SOURCES.len() {
            if i > 0 {
                sql.push(" UNION ALL ");
            }
            sql.push("SELECT * FROM owner_").push(i);
            self.eligible(sql)?;
        }
        sql.push(") eligible LIMIT ")
            .push_bind(budget as i64 + 1)
            .push(")");
        ambiguity(sql, false);
        sql.push(" SELECT count(*),count(*) FILTER(WHERE kind='command'),count(*) FILTER(WHERE kind='action_run'),count(*) FILTER(WHERE status='unknown'),CASE WHEN count(*)<=")
            .push_bind(budget as i64).push(" THEN EXISTS(SELECT FROM ambiguous) ELSE FALSE END FROM selected");
        Ok(())
    }
}

// Membership uses only tenant + selected IDs. Never hide a conflicting owner behind
// a different device, metadata predicate, seek position, or public projection.
fn ambiguity(sql: &mut QueryBuilder<Postgres>, page: bool) {
    if page {
        // Bounded by the public page or the explicit sort-input ceiling.
        sql.push(",candidate_keys AS (SELECT array_agg(id) AS ids FROM selected)");
    } else {
        // A whole-statistic join can choose to scan unrelated tenant history. Probe
        // the same indexed keys as a page, bounding each array independently. The
        // relational grouping and selected tuplestore can spill under work_mem.
        sql.push(",candidate_keys AS (SELECT array_agg(id) AS ids FROM (SELECT id, (row_number() OVER () - 1) / ")
            .push(selection::BATCH).push(" AS batch FROM selected) numbered GROUP BY batch)");
    }
    sql.push(",ambiguous AS (SELECT duplicates.id FROM candidate_keys k CROSS JOIN LATERAL (SELECT id FROM (");
    for (i, source) in SOURCES.iter().enumerate() {
        if i > 0 {
            sql.push(" UNION ALL ");
        }
        sql.push("SELECT id FROM ");
        if let Some(identities) = source.identities {
            sql.push("(").push(identities).push(") owned");
        } else {
            sql.push("owner_").push(i);
        }
        sql.push(" WHERE id=ANY(k.ids)");
    }
    sql.push(") memberships GROUP BY id HAVING count(*)>1");
    if page {
        sql.push(") duplicates)");
    } else {
        sql.push(" LIMIT 1) duplicates LIMIT 1)");
    }
}
