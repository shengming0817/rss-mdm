//! Policy event records. The initiating application owns authorization and settlement.
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde_json::Value;
use sqlx::postgres::PgRow;
use uuid::Uuid;
/// Read the original accepted batch by caller and operation identity.
pub async fn replay_in(
    tx: &mut PgTransaction<'_>,
    actor: String,
    operation: Uuid,
) -> Result<Option<(Vec<u8>, Uuid, i64)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,'policy-event',$2::text,$3::text)::text,2889))")
            .bind(&tenant).bind(&actor).bind(operation.to_string()).execute(&mut *c).await?;
        sqlx::query_as("SELECT fingerprint,id,(SELECT count(*) FROM mdm_policy.event_members m WHERE(m.tenant_id,m.batch)=(b.tenant_id,b.id)) FROM mdm_policy.event_batches b WHERE tenant_id=$1::uuid AND actor=$2 AND request=$3").bind(tenant).bind(actor).bind(operation).fetch_optional(c).await })).await
}
/// Bound candidates for one event name before freezing its member set.
pub async fn matching_policies_in(
    tx: &mut PgTransaction<'_>,
    name: String,
) -> Result<Vec<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move { sqlx::query_scalar("SELECT id FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND definition->>'customEvent'=$2 AND state<>'archived' ORDER BY id LIMIT 1001").bind(tenant).bind(name).fetch_all(c).await })).await
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
pub async fn insert_batch_in(tx: &mut PgTransaction<'_>, batch: Batch) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move { sqlx::query("INSERT INTO mdm_policy.event_batches(tenant_id,id,request,actor,caller,device,input,fingerprint,created_at,deadline) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(tenant).bind(batch.id).bind(batch.operation).bind(batch.actor).bind(batch.caller).bind(batch.device).bind(batch.input).bind(batch.fingerprint).bind(batch.at).bind(batch.deadline).execute(c).await?; Ok(()) })).await
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
pub async fn insert_member_in(tx: &mut PgTransaction<'_>, member: Member) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move { sqlx::query("INSERT INTO mdm_policy.event_members(tenant_id,batch,id,policy,revision,version,target,authority,decision) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)").bind(tenant).bind(member.batch).bind(member.id).bind(member.policy).bind(member.revision).bind(member.version).bind(member.target).bind(member.authority).bind(member.decision).execute(c).await?; Ok(()) })).await
}
/// Lock one pending member until its decision and execution effects settle.
pub async fn pending_member_in(
    tx: &mut PgTransaction<'_>,
    batch: Uuid,
) -> Result<Option<PgRow>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move { sqlx::query("SELECT b.caller,b.input,b.deadline,m.id,m.policy,m.version,m.target,m.authority FROM mdm_policy.event_batches b JOIN mdm_policy.event_members m ON(m.tenant_id,m.batch)=(b.tenant_id,b.id) WHERE b.tenant_id=$1::uuid AND b.id=$2 AND m.decision->>'state'='pending' ORDER BY m.id LIMIT 1 FOR UPDATE OF m").bind(tenant).bind(batch).fetch_optional(c).await })).await
}
/// Persist the decision alongside execution effects and audit.
pub async fn decide_member_in(
    tx: &mut PgTransaction<'_>,
    member: Uuid,
    decision: Value,
) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move { sqlx::query("UPDATE mdm_policy.event_members SET decision=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(tenant).bind(member).bind(decision).execute(c).await?; Ok(()) })).await
}
/// Record a terminal rejection only after confirmed rollback and claim validation.
pub async fn reject_next_in(
    tx: &mut PgTransaction<'_>,
    batch: Uuid,
    decision: Value,
) -> Result<Option<Uuid>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move { sqlx::query_scalar("UPDATE mdm_policy.event_members SET decision=$3 WHERE tenant_id=$1::uuid AND id=(SELECT id FROM mdm_policy.event_members WHERE tenant_id=$1::uuid AND batch=$2 AND decision->>'state'='pending' ORDER BY id LIMIT 1) RETURNING id").bind(tenant).bind(batch).bind(decision).fetch_optional(c).await })).await
}
/// Read links needed to append the original member activity.
pub async fn member_fact_in(tx: &mut PgTransaction<'_>, member: Uuid) -> Result<PgRow, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move { sqlx::query("SELECT m.target,m.policy,m.version,b.request,b.input FROM mdm_policy.event_members m JOIN mdm_policy.event_batches b ON(b.tenant_id,b.id)=(m.tenant_id,m.batch) WHERE m.tenant_id=$1::uuid AND m.id=$2").bind(tenant).bind(member).fetch_one(c).await })).await
}
