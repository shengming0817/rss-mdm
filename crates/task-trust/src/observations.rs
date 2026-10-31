//! Dedicated task_trust observations. No observation writes rotation acknowledgements.
//! ref: sqlx v0.8.6 sqlx-postgres/src/transaction.rs (caller-owned transaction).
use crate::Error;
use rss_mdm_agent_wire::task_trust::{Observation, ObservedInstallation};
use sqlx::PgConnection;
pub const INSTALL_SQL: &str = include_str!("observations.sql");
fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(crate::Failure::Database)
}
/// Persist a report in the authenticated owner's transaction. Exact replay retains receipt time.
pub async fn record_in(
    c: &mut PgConnection,
    tenant: &str,
    input: &Observation,
) -> Result<bool, Error> {
    input.validate().map_err(|_| Error::Conflict)?;
    let body = serde_json::to_value(input).map_err(|_| Error::Conflict)?;
    let inserted = sqlx::query("INSERT INTO mdm_task_signing.trust_observations(tenant_id,registration,generation,sequence,operation,body) VALUES($1::uuid,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
        .bind(tenant).bind(input.registration).bind(input.generation as i64).bind(input.sequence as i64)
        .bind(input.operation).bind(&body).execute(&mut *c).await.map_err(db)?.rows_affected();
    if inserted == 1 {
        return Ok(false);
    }
    let previous: Option<serde_json::Value> = sqlx::query_scalar("SELECT body FROM mdm_task_signing.trust_observations WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(tenant).bind(input.operation).fetch_optional(c).await.map_err(db)?;
    if previous.as_ref() != Some(&body) {
        return Err(Error::Conflict);
    }
    Ok(true)
}
/// Only the current registration generation is eligible; device clock never orders reports.
pub async fn latest_in(
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Option<ObservedInstallation>, Error> {
    let row: Option<(serde_json::Value,i64)> = sqlx::query_as("SELECT o.body,o.received_at FROM mdm_task_signing.trust_observations o JOIN mdm_access.registrations r ON (r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.generation) WHERE r.tenant_id=$1::uuid AND r.device=$2 AND r.channel='agent' AND r.state='active' ORDER BY o.sequence DESC LIMIT 1")
        .bind(tenant).bind(device).fetch_optional(c).await.map_err(db)?;
    row.map(|(body, received_at)| {
        Ok(ObservedInstallation {
            observation: serde_json::from_value(body).map_err(|_| Error::Conflict)?,
            received_at,
        })
    })
    .transpose()
}
