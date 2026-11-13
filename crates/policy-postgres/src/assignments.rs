//! Policy assignment facts; business availability and withdrawal decisions belong to Policy.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use uuid::Uuid;
/// One assignment projection decided by the Policy application.
pub struct Assignment {
    /// Owning Policy identity.
    pub policy: Uuid,
    /// Immutable publication identity.
    pub version: Uuid,
    /// Typed endpoint or association identity.
    pub object: rss_mdm_agent_wire::ObjectRef,
    /// Chosen channel.
    pub channel: String,
    /// Complete bounded assignment facts.
    pub input: Value,
    /// Current availability decided by the application.
    pub available: bool,
    /// Closed reason for unavailability.
    pub reason: Option<String>,
    /// Exact registration target, when available.
    pub target: Option<Value>,
    /// Frozen Scope result identity.
    pub scope_result: Uuid,
    /// OncePerEntry coordinate, independent of ordinary observation watermarks.
    pub entry_revision: i64,
}
/// Publish a changed assignment in the initiating transaction.
pub async fn upsert_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    a: Assignment,
) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).assignments_upsert_in_1)
                .bind(tenant)
                .bind(a.policy)
                .bind(a.version)
                .bind(a.object.kind())
                .bind(a.object.uuid())
                .bind(a.channel)
                .bind(a.input)
                .bind(if a.available { "ready" } else { "unavailable" })
                .bind(a.reason)
                .bind(a.target)
                .bind(a.scope_result)
                .bind(a.entry_revision)
                .execute(c)
                .await
                .map(|r| r.rows_affected() > 0)
        })
    })
    .await
}
/// Read existing objects for reference-membership verification by Scope.
pub async fn objects_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
    version: Uuid,
) -> Result<Vec<rss_mdm_agent_wire::ObjectRef>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_as::<_, (i16, Uuid)>(
                crate::storage_profile::sql(profile).assignments_objects_in_1,
            )
            .bind(tenant)
            .bind(policy)
            .bind(version)
            .fetch_all(c)
            .await
            .and_then(|rows| {
                rows.into_iter()
                    .map(|(kind, id)| {
                        rss_mdm_agent_wire::ObjectRef::from_parts(kind, id)
                            .map_err(|e| sqlx::Error::Decode(Box::new(e)))
                    })
                    .collect()
            })
        })
    })
    .await
}
/// Withdraw only objects proved absent by the Scope reference reader.
pub async fn withdraw_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
    version: Uuid,
    objects: Vec<rss_mdm_agent_wire::ObjectRef>,
) -> Result<Vec<(rss_mdm_agent_wire::ObjectRef, Option<Value>)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_as::<_, (i16, Uuid, Option<Value>)>(
                crate::storage_profile::sql(profile).assignments_withdraw_in_1,
            )
            .bind(tenant)
            .bind(policy)
            .bind(version)
            .bind(objects.iter().map(|o| o.kind()).collect::<Vec<_>>())
            .bind(objects.iter().map(|o| o.uuid()).collect::<Vec<_>>())
            .fetch_all(c)
            .await
            .and_then(|rows| {
                rows.into_iter()
                    .map(|(kind, id, target)| {
                        Ok((
                            rss_mdm_agent_wire::ObjectRef::from_parts(kind, id)
                                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
                            target,
                        ))
                    })
                    .collect()
            })
        })
    })
    .await
}
