//! Query catalogs and SQL belong to the Policy storage owner.
use rss_mdm_query::{
    Error as QueryError,
    directory::{Field, Kind, Position, Query, Schema},
};
use rss_mdm_query_postgres::Source;
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
/// Trusted current Policy storage roots; checked against the service model.
pub static SOURCES: &[rss_mdm_query_postgres::Source] = &[
    Source::column("id", "id::text COLLATE \"C\""),
    Source::column(
        "toolName",
        "('policy_' || replace(id::text,'-','')) COLLATE \"C\"",
    ),
    Source::column("alias", "(definition->>'alias') COLLATE \"C\""),
    Source::column("customEvent", "(definition->>'customEvent') COLLATE \"C\""),
    Source::column("revision", "revision"),
    Source::column("version", "version_number"),
    Source::column("versionId", "current_version::text COLLATE \"C\""),
    Source::column("state", "state COLLATE \"C\""),
    Source::column("action", "(definition->'action'->>'kind') COLLATE \"C\""),
    Source::column("scope", "(definition->>'scope') COLLATE \"C\""),
    Source::column(
        "resource",
        "(definition->'action'->'resource'->>'id') COLLATE \"C\"",
    ),
    Source::column(
        "category",
        "(definition->'selfService'->'presentation'->>'category') COLLATE \"C\"",
    ),
    Source::json("definition", "definition"),
];
/// Event batch directory fields.
pub static BATCHES: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema {
    id: "policy_event_batches",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: vec![
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
});
/// Event member directory fields.
pub static MEMBERS: std::sync::LazyLock<Schema> = std::sync::LazyLock::new(|| Schema {
    id: "policy_event_members",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: vec![
        Field::scalar("id", Kind::Uuid),
        Field::scalar("policyId", Kind::Uuid),
        Field::scalar("versionId", Kind::Uuid),
        Field::scalar("state", Kind::Text),
        Field::output("revision"),
        Field::output("decision"),
        Field::output("operations"),
    ],
});
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

/// Read a bounded management directory page from a checked query.
pub async fn policies_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    q: &Query,
    after: Option<&Position>,
    bindings: &rss_mdm_query_postgres::Bindings,
) -> Result<Vec<Value>, Error> {
    q.require_schema(bindings.schema())?;
    let mut sql =
        sqlx::QueryBuilder::new(crate::storage_profile::sql(profile).directory_policies_in_1);
    sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
    if !q.mentions("state") {
        sql.push(" AND state<>'archived'");
    }
    rss_mdm_query_postgres::append(&mut sql, q, after, bindings)?;
    Ok(tx
        .with_connection(move |c| {
            Box::pin(async move { sql.build_query_scalar().fetch_all(c).await })
        })
        .await?)
}
/// Device and optional batch/registration coordinates already authorized by the caller.
pub struct EventTarget<'a> {
    /// Visible device identity.
    pub device: &'a str,
    /// Optional accepted batch identity.
    pub batch: Option<Uuid>,
}
/// Read a bounded device-specific batch or member page. Authorization remains with the caller.
pub async fn events_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    q: &Query,
    after: Option<&Position>,
    target: EventTarget<'_>,
    members: bool,
) -> Result<Vec<Value>, Error> {
    let EventTarget { device, batch } = target;
    q.require_schema(if members { &MEMBERS } else { &BATCHES })?;
    let prefix = if members {
        crate::storage_profile::sql(profile).directory_events_in_1
    } else {
        crate::storage_profile::sql(profile).directory_event_batches
    };
    let mut sql = sqlx::QueryBuilder::new(prefix);
    sql.push_bind(tx.tenant_id().to_string())
        .push("::uuid AND b.device=")
        .push_bind(device.to_owned());
    if let Some(batch) = batch {
        sql.push(" AND b.id=").push_bind(batch);
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
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    id: Uuid,
    device: String,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).directory_batch_exists_in_1)
                .bind(tenant)
                .bind(id)
                .bind(device)
                .fetch_one(c)
                .await
        })
    })
    .await
}
