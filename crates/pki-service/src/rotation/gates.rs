//! The original transition predicates, shared by diagnostics and the fenced write transaction.
use super::*;
use sqlx::{Postgres, QueryBuilder};

// No projection join may remove a blocking fact. Missing associations remain nullable.

fn sql(
    profile: rss_mdm_install_support::StorageProfile,
    tenant: &str,
    id: Uuid,
    now: i64,
) -> QueryBuilder<Postgres> {
    let mut sql = QueryBuilder::new("WITH params AS (SELECT ");
    sql.push_bind(tenant.to_owned())
        .push("::uuid AS tenant,")
        .push_bind(id)
        .push("::uuid AS id,")
        .push_bind(now)
        .push("::bigint AS now")
        .push(crate::storage_profile::sql(profile).rotation_relations);
    sql
}
pub(crate) async fn kinds(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
    now: i64,
) -> Result<Vec<BlockerKind>, Error> {
    let values: Vec<String> = sql(profile, tenant, id, now)
        .push("SELECT DISTINCT kind FROM blockers ORDER BY kind")
        .build_query_scalar()
        .fetch_all(c)
        .await
        .map_err(db)?;
    values
        .into_iter()
        .map(|v| serde_json::from_value(serde_json::Value::String(v)).map_err(|_| Error::Storage))
        .collect()
}
pub(crate) async fn require(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
    state: RotationState,
    now: i64,
) -> Result<(), Error> {
    let actual: String =
        sqlx::query_scalar(crate::storage_profile::sql(profile).rotation_gates_require_1)
            .bind(tenant)
            .bind(id)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if !matches!(
        (actual.as_str(), state),
        ("distributing", RotationState::Activated) | ("activated", RotationState::Retired)
    ) {
        return Err(Error::Conflict);
    }
    let blocked: bool = sql(profile, tenant, id, now)
        .push("SELECT EXISTS(SELECT 1 FROM blockers)")
        .build_query_scalar()
        .fetch_one(c)
        .await
        .map_err(db)?;
    if blocked {
        Err(Error::Conflict)
    } else {
        Ok(())
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "bounded blocker read retains product, key, fact time and signed cursor coordinates"
)]
pub(super) async fn page(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
    now: i64,
    q: &Query,
    codec: &CursorCodec,
    binding: &str,
) -> Result<Page<Projection<Blocker>>, Error> {
    let after = q.after(codec, binding).map_err(query_error)?;
    let mut sql = sql(profile, tenant, id, now);
    sql.push("SELECT jsonb_build_object('kind',kind,'id',id,'device',device,'state',state,'deadline',deadline,'revocationState',revocation_state) FROM blockers WHERE true");
    rss_mdm_query_postgres::append(&mut sql, q, after.as_ref(), &*BLOCKER_BINDINGS)
        .map_err(query_error)?;
    let rows: Vec<serde_json::Value> = sql.build_query_scalar().fetch_all(c).await.map_err(db)?;
    let rows = rows
        .into_iter()
        .map(serde_json::from_value::<Blocker>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::Storage)?;
    q.page_typed(rows, codec, binding).map_err(query_error)
}
