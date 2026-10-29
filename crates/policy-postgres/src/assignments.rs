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
    /// Canonical object key.
    pub object: String,
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
pub async fn upsert_in(tx: &mut PgTransaction<'_>, a: Assignment) -> Result<bool, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
 sqlx::query("INSERT INTO mdm_policy.assignments(tenant_id,policy,version,object,channel,input,availability,reason,target,scope_result,entry_revision) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant_id,policy,version,object,channel) DO UPDATE SET input=EXCLUDED.input,availability=EXCLUDED.availability,reason=EXCLUDED.reason,target=EXCLUDED.target,scope_result=EXCLUDED.scope_result,entry_revision=EXCLUDED.entry_revision WHERE (assignments.input,assignments.availability,assignments.reason,assignments.target,assignments.scope_result,assignments.entry_revision) IS DISTINCT FROM (EXCLUDED.input,EXCLUDED.availability,EXCLUDED.reason,EXCLUDED.target,EXCLUDED.scope_result,EXCLUDED.entry_revision)").bind(tenant).bind(a.policy).bind(a.version).bind(a.object).bind(a.channel).bind(a.input).bind(if a.available {"ready"}else{"unavailable"}).bind(a.reason).bind(a.target).bind(a.scope_result).bind(a.entry_revision).execute(c).await.map(|r|r.rows_affected()>0)
 })).await
}
/// Read existing objects for reference-membership verification by Scope.
pub async fn objects_in(
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
    version: Uuid,
) -> Result<Vec<(String, Value)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query_as("SELECT object,input->'object' FROM mdm_policy.assignments WHERE tenant_id=$1::uuid AND policy=$2 AND version=$3 AND reason IS DISTINCT FROM 'source_removed'").bind(tenant).bind(policy).bind(version).fetch_all(c).await})).await
}
/// Withdraw only objects proved absent by the Scope reference reader.
pub async fn withdraw_in(
    tx: &mut PgTransaction<'_>,
    policy: Uuid,
    version: Uuid,
    objects: Vec<String>,
) -> Result<Vec<(String, Option<Value>)>, PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {sqlx::query_as("UPDATE mdm_policy.assignments SET input=jsonb_set(jsonb_set(jsonb_set(input,'{availability}','\"unavailable\"'),'{reason}','\"source_removed\"'),'{admission}','{\"state\":\"excluded\"}'),availability='unavailable',reason='source_removed',entry_revision=0 WHERE tenant_id=$1::uuid AND policy=$2 AND version=$3 AND object=ANY($4::text[]) AND reason IS DISTINCT FROM 'source_removed' RETURNING object,target").bind(tenant).bind(policy).bind(version).bind(objects).fetch_all(c).await})).await
}
