//! Query catalogs and SQL belong to the Policy storage owner.
use rss_mdm_query::{
    Error as QueryError,
    directory::{Field, Kind, Position, Query, Schema},
};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use uuid::Uuid;
/// Query compilation or provider failure, preserved until the initiating application settles.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Checked query rejection.
    #[error(transparent)]
    Query(#[from] QueryError),
    /// Provider failure.
    #[error(transparent)]
    Storage(#[from] PgError),
}
/// Management Policy directory fields.
pub static SCHEMA: Schema = Schema {
    id: "policies",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("toolName", Kind::Text),
        Field::scalar("alias", Kind::Text),
        Field::scalar("customEvent", Kind::Text),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("version", Kind::Integer),
        Field::scalar("state", Kind::Enum(&["enabled", "disabled", "archived"])),
        Field::scalar(
            "action",
            Kind::Enum(&[
                "device_access",
                "unmanage_device",
                "credential",
                "execution",
                "native_collection",
                "agent_collection",
                "telemetry_profile",
                "configuration",
                "software",
                "ensure_agent_installed",
                "request_mdm_enrollment",
            ]),
        ),
        Field::scalar("scope", Kind::Uuid),
        Field::scalar("resource", Kind::Text),
        Field::scalar("category", Kind::Text),
        Field::output("versionId"),
        Field::output("definition"),
    ],
};
/// Parse the management directory query against its canonical fields.
pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    SCHEMA.parse(raw)
}
fn column(name: &str) -> &'static str {
    match name {
        "id" => "id::text COLLATE \"C\"",
        "toolName" => "('policy_' || replace(id::text,'-','')) COLLATE \"C\"",
        "alias" => "(definition->>'alias') COLLATE \"C\"",
        "customEvent" => "(definition->>'customEvent') COLLATE \"C\"",
        "revision" => "revision",
        "version" => "version_number",
        "state" => "state COLLATE \"C\"",
        "action" => "(definition->'action'->>'kind') COLLATE \"C\"",
        "scope" => "(definition->>'scope') COLLATE \"C\"",
        "resource" => "(definition->'action'->'resource'->>'id') COLLATE \"C\"",
        "category" => "(definition->'selfService'->'presentation'->>'category') COLLATE \"C\"",
        _ => unreachable!("checked Policy field"),
    }
}
/// Event batch directory fields.
pub static BATCHES: Schema = Schema {
    id: "policy_event_batches",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("operationId", Kind::Uuid),
        Field::scalar("event", Kind::Text),
        Field::scalar("createdAt", Kind::Integer),
        Field::output("deadline"),
        Field::output("members"),
        Field::output("admission"),
        Field::output("request"),
        Field::output("processingFailure"),
    ],
};
/// Event member directory fields.
pub static MEMBERS: Schema = Schema {
    id: "policy_event_members",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("policyId", Kind::Uuid),
        Field::scalar("versionId", Kind::Uuid),
        Field::scalar("state", Kind::Text),
        Field::output("revision"),
        Field::output("decision"),
        Field::output("operations"),
    ],
};
fn batch_column(name: &str) -> &'static str {
    match name {
        "id" => "b.id::text COLLATE \"C\"",
        "operationId" => "b.request::text COLLATE \"C\"",
        "event" => "(b.input->>'event') COLLATE \"C\"",
        "createdAt" => "b.created_at",
        _ => unreachable!("checked batch field"),
    }
}
fn member_column(name: &str) -> &'static str {
    match name {
        "id" => "m.id::text COLLATE \"C\"",
        "policyId" => "m.policy::text COLLATE \"C\"",
        "versionId" => "m.version::text COLLATE \"C\"",
        "state" => "(m.decision->>'state') COLLATE \"C\"",
        _ => unreachable!("checked member field"),
    }
}
const BATCH_SELECT: &str = "SELECT jsonb_build_object('request',b.input,'id',b.id,'operationId',b.request,'event',b.input->>'event','createdAt',b.created_at,'deadline',b.deadline,'processingFailure',(SELECT failure FROM mdm_policy.work WHERE tenant_id=b.tenant_id AND id=b.id),'members',(SELECT count(*) FROM mdm_policy.event_members m WHERE(m.tenant_id,m.batch)=(b.tenant_id,b.id)),'admission',(SELECT coalesce(jsonb_object_agg(state,n),'{}'::jsonb) FROM(SELECT decision->>'state' state,count(*) n FROM mdm_policy.event_members WHERE tenant_id=b.tenant_id AND batch=b.id GROUP BY decision->>'state') counts)) FROM mdm_policy.event_batches b WHERE b.tenant_id=";

/// Read a bounded management directory page from a checked query.
pub async fn policies_in(
    tx: &mut PgTransaction<'_>,
    q: &Query,
    after: Option<&Position>,
) -> Result<Vec<Value>, Error> {
    q.require_schema(&SCHEMA)?;
    let mut sql = sqlx::QueryBuilder::new(
        "SELECT jsonb_build_object('id',id,'toolName','policy_' || replace(id::text,'-',''),'alias',definition->>'alias','customEvent',definition->>'customEvent','revision',revision,'version',version_number,'versionId',current_version,'state',state,'definition',definition,'action',definition->'action'->>'kind','scope',definition->>'scope','resource',definition->'action'->'resource'->>'id','category',definition->'selfService'->'presentation'->>'category') FROM mdm_policy.policies WHERE tenant_id=",
    );
    sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
    if !q.mentions("state") {
        sql.push(" AND state<>'archived'");
    }
    rss_mdm_query_postgres::append(&mut sql, q, after, column)?;
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
        })
        .await?)
}
/// Read a bounded device-specific batch or member page. Authorization remains with the caller.
pub async fn events_in(
    tx: &mut PgTransaction<'_>,
    q: &Query,
    after: Option<&Position>,
    device: &str,
    batch: Option<Uuid>,
    registration: Option<Uuid>,
    members: bool,
) -> Result<Vec<Value>, Error> {
    q.require_schema(if members { &MEMBERS } else { &BATCHES })?;
    let prefix = if members {
        "SELECT jsonb_build_object('id',m.id,'policyId',m.policy,'versionId',m.version,'revision',m.revision,'state',m.decision->>'state','decision',m.decision) FROM mdm_policy.event_members m JOIN mdm_policy.event_batches b ON(b.tenant_id,b.id)=(m.tenant_id,m.batch) WHERE b.tenant_id="
    } else {
        BATCH_SELECT
    };
    let mut sql = sqlx::QueryBuilder::new(prefix);
    sql.push_bind(tx.tenant_id().to_string())
        .push("::uuid AND b.device=")
        .push_bind(device.to_owned());
    if let Some(batch) = batch {
        sql.push(" AND b.id=").push_bind(batch);
    }
    if let Some(registration) = registration {
        sql.push(" AND b.caller->'target'->>'registration'=")
            .push_bind(registration.to_string());
    }
    rss_mdm_query_postgres::append(
        &mut sql,
        q,
        after,
        if members { member_column } else { batch_column },
    )?;
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
        })
        .await?)
}
/// Check a batch belongs to the visible device before returning a detail page.
pub async fn batch_exists_in(
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    device: String,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.event_batches WHERE tenant_id=$1::uuid AND id=$2 AND device=$3)").bind(tenant).bind(id).bind(device).fetch_one(c).await})).await
}
