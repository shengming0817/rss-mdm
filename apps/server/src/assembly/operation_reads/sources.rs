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
        Source {
            identities: Some(rss_mdm_device_access_postgres::device_access::execution::storage::IDENTITY_RELATION),
            ..source(rss_mdm_device_access_postgres::device_access::execution::queries::RELATION_SQL,
                None, Some(Run::Access))
        },
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
        source(
            rss_mdm_script_service::queries::RELATION_SQL,
            None,
            Some(Run::Script),
        ),
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

pub(crate) struct Scope<'a> {
    tenant: String,
    devices: Option<Vec<Uuid>>,
    query: &'a Query,
}

impl<'a> Scope<'a> {
    pub(crate) fn new(tenant: String, devices: Option<Vec<Uuid>>, query: &'a Query) -> Self {
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
        sql.push(",selected AS MATERIALIZED (SELECT * FROM (");
        for i in 0..SOURCES.len() {
            if i > 0 {
                sql.push(" UNION ALL ");
            }
            sql.push("(SELECT *,")
                .push(i)
                .push(" AS source FROM owner_")
                .push(i);
            self.eligible(sql)?;
            // The inclusive leading range lets a B-tree skip the discarded prefix of
            // late identity pages. page_limit still checks the complete lexicographic key.
            if let Some(after) = after
                && let Some(key) = self.query.sort().first().filter(|k| k.field == "id")
                && let Some(id) = after.0.first().and_then(Value::as_str)
            {
                sql.push(if key.descending {
                    " AND id<="
                } else {
                    " AND id>="
                })
                .push_bind(Uuid::parse_str(id).map_err(|_| Error::QueryCursorInvalidated)?);
            }
            rss_mdm_query_postgres::page_limit(sql, self.query, after, &*BINDINGS, size)
                .map_err(query_error)?;
            sql.push(")");
        }
        sql.push(") merged");
        rss_mdm_query_postgres::order(sql, self.query, &*BINDINGS).map_err(query_error)?;
        sql.push(" LIMIT ").push_bind(size as i64).push(")");
        ambiguity(sql, true);
        sql.push(" SELECT jsonb_build_object('id',id,'kind',kind,'device',device,'origin',source_kind,'policy',policy,'deadline',deadline,'status',status,'source',source,'inputBytes',input_bytes) AS document, EXISTS(SELECT FROM ambiguous) AS ambiguous FROM selected");
        rss_mdm_query_postgres::order(sql, self.query, &*BINDINGS).map_err(query_error)
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
        // At most one key per candidate in a single bounded fetch.
        sql.push(",candidate_keys AS MATERIALIZED (SELECT array_agg(id) AS ids FROM selected)");
    }
    sql.push(",ambiguous AS (SELECT memberships.id FROM (");
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
        if page {
            sql.push(" WHERE id=ANY((SELECT ids FROM candidate_keys)::uuid[])");
        }
    }
    sql.push(") memberships");
    if !page {
        // Let PostgreSQL join or spill large sets under work_mem. A single exact
        // statistic can contain millions of candidates; never pack it into one array.
        sql.push(" JOIN selected USING(id)");
    }
    sql.push(" GROUP BY memberships.id HAVING count(*)>1 LIMIT 1)");
}
