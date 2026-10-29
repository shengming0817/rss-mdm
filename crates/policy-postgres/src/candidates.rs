//! Bounded Policy candidate data consumed by Execution.
use rss_request_context::TenantId;
use sqlx::{PgConnection, postgres::PgRow};
use uuid::Uuid;
/// Native interest for an exact current device assignment.
pub async fn native_interest_on(
    c: &mut PgConnection,
    tenant: TenantId,
    device: &str,
    kinds: &[&str],
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_policy.policies p JOIN mdm_policy.assignments a ON(a.tenant_id,a.policy,a.version)=(p.tenant_id,p.id,p.current_version) WHERE p.tenant_id=$1::uuid AND (p.state='enabled') AND (p.definition->'action'->>'kind'=ANY($3::text[]) OR (p.definition->'action'->>'kind'='software' AND p.definition->'action'->>'channel'='mdm')) AND a.channel='mdm' AND a.target->>'device'=$2 AND a.input->'admission'->>'state'<>'excluded')").bind(tenant.to_string()).bind(device).bind(kinds).fetch_one(c).await
}
/// Bounded configuration candidates and the Execution-owned channel projection.
pub async fn configuration_candidates_on(
    c: &mut PgConnection,
    tenant: TenantId,
    devices: &[String],
    after: Option<&(Uuid, String)>,
) -> Result<Vec<PgRow>, sqlx::Error> {
    sqlx::query("WITH candidates AS MATERIALIZED (SELECT p.id,p.current_version,(p.definition->>'scope')::uuid AS scope,d.device FROM mdm_policy.policies p CROSS JOIN (SELECT DISTINCT unnest($2::text[]) AS device) d WHERE p.tenant_id=$1::uuid AND p.state='enabled' AND p.definition->'action'->>'kind'='configuration' AND ($3::uuid IS NULL OR (p.id,d.device COLLATE \"C\")>($3,$4 COLLATE \"C\")) ORDER BY p.id,d.device COLLATE \"C\" LIMIT 1001) SELECT *,mdm_commands.channel_admission(scope,'mdm',device) AS admission FROM candidates ORDER BY id,device COLLATE \"C\"").bind(tenant.to_string()).bind(devices).bind(after.map(|v|v.0)).bind(after.map(|v|v.1.as_str())).fetch_all(c).await
}
/// One bounded action-kind candidate page, including a lookahead row.
pub async fn candidates_on(
    c: &mut PgConnection,
    tenant: TenantId,
    after: Uuid,
    kind: &str,
) -> Result<Vec<PgRow>, sqlx::Error> {
    sqlx::query("SELECT id,current_version,(definition->>'scope')::uuid AS scope FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND (state='enabled') AND id>$2 AND definition->'action'->>'kind'=$3 ORDER BY id LIMIT 17").bind(tenant.to_string()).bind(after).bind(kind).fetch_all(c).await
}
