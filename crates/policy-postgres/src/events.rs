//! Policy event records. The initiating application owns authorization and settlement.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use sqlx::postgres::PgRow;
use uuid::Uuid;
/// Read the original accepted batch by caller and operation identity.
pub async fn replay_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    actor: String,
    operation: Uuid,
) -> Result<Option<(Vec<u8>, Uuid, i64)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,'policy-event',$2::text,$3::text)::text,2889))")
            .bind(&tenant).bind(&actor).bind(operation.to_string()).execute(&mut *c).await?;
        sqlx::query_as(crate::storage_profile::sql(profile).events_replay_in_1).bind(tenant).bind(actor).bind(operation).fetch_optional(c).await })).await
}
/// Bound candidates for one event name before freezing its member set.
pub async fn matching_policies_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    name: String,
) -> Result<Vec<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).events_matching_policies_in_1)
                .bind(tenant)
                .bind(name)
                .fetch_all(c)
                .await
        })
    })
    .await
}
/// Accepted batch facts decided by the Policy application.
pub struct Batch {
    /// Stable batch identity.
    pub id: Uuid,
    /// Original caller operation identity.
    pub operation: Uuid,
    /// Canonical caller key.
    pub actor: String,
    /// Complete caller provenance.
    pub caller: Value,
    /// Target device identity.
    pub device: String,
    /// Original validated event input.
    pub input: Value,
    /// Complete replay fingerprint.
    pub fingerprint: Vec<u8>,
    /// Acceptance time.
    pub at: i64,
    /// Last admissible execution time.
    pub deadline: i64,
}
/// Insert one accepted batch in the original operation transaction.
pub async fn insert_batch_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    batch: Batch,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).events_insert_batch_in_1)
                .bind(tenant)
                .bind(batch.id)
                .bind(batch.operation)
                .bind(batch.actor)
                .bind(batch.caller)
                .bind(batch.device)
                .bind(batch.input)
                .bind(batch.fingerprint)
                .bind(batch.at)
                .bind(batch.deadline)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
/// One original member and the Policy facts accepted for it.
pub struct Member {
    /// Original batch identity.
    pub batch: Uuid,
    /// Stable member identity, reused by execution.
    pub id: Uuid,
    /// Policy identity.
    pub policy: Uuid,
    /// Accepted definition revision.
    pub revision: i64,
    /// Accepted semantic execution version.
    pub version: Uuid,
    /// Exact registration and generation.
    pub target: Value,
    /// Frozen authority coordinates.
    pub authority: Value,
    /// Initial member decision.
    pub decision: Value,
}
/// Freeze the accepted Policy version and member authority.
pub async fn insert_member_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    member: Member,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).events_insert_member_in_1)
                .bind(tenant)
                .bind(member.batch)
                .bind(member.id)
                .bind(member.policy)
                .bind(member.revision)
                .bind(member.version)
                .bind(member.target)
                .bind(member.authority)
                .bind(member.decision)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
/// Lock one pending member until its decision and execution effects settle.
pub async fn pending_member_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    batch: Uuid,
) -> Result<Option<PgRow>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).events_pending_member_in_1)
                .bind(tenant)
                .bind(batch)
                .fetch_optional(c)
                .await
        })
    })
    .await
}
/// Persist the decision alongside execution effects and audit.
pub async fn decide_member_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    member: Uuid,
    decision: Value,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).events_decide_member_in_1)
                .bind(tenant)
                .bind(member)
                .bind(decision)
                .execute(c)
                .await?;
            Ok(())
        })
    })
    .await
}
/// Record a terminal rejection only after confirmed rollback and claim validation.
pub async fn reject_next_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    batch: Uuid,
    decision: Value,
) -> Result<Option<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query_scalar(crate::storage_profile::sql(profile).events_reject_next_in_1)
                .bind(tenant)
                .bind(batch)
                .bind(decision)
                .fetch_optional(c)
                .await
        })
    })
    .await
}
/// Read links needed to append the original member activity.
pub async fn member_fact_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut PgTransaction<'_>,
    member: Uuid,
) -> Result<PgRow, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c| {
        Box::pin(async move {
            sqlx::query(crate::storage_profile::sql(profile).events_member_fact_in_1)
                .bind(tenant)
                .bind(member)
                .fetch_one(c)
                .await
        })
    })
    .await
}
