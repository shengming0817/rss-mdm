//! Dedicated task_trust observations. No observation writes rotation acknowledgements.
//! ref: sqlx v0.8.6 sqlx-postgres/src/transaction.rs (caller-owned transaction).
use crate::Error;
use rss_mdm_agent_wire::task_trust::{Observation, ObservedInstallation};
use sqlx::PgConnection;
pub const fn install_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    crate::storage_profile::sql(profile, crate::Use::AgentTask).observations_install
}
fn db(_: sqlx::Error) -> Error {
    Error::Unavailable(crate::Failure::Database)
}
/// Persist a report in the authenticated owner's transaction. Exact replay retains receipt time.
pub async fn record_in(
    profile: rss_mdm_install_support::StorageProfile,
    usage: crate::Use,
    c: &mut PgConnection,
    tenant: &str,
    input: &Observation,
) -> Result<bool, Error> {
    input.validate().map_err(|_| Error::Conflict)?;
    let body = serde_json::to_value(input).map_err(|_| Error::Conflict)?;
    let inserted =
        sqlx::query(crate::storage_profile::sql(profile, usage).observations_record_in_1)
            .bind(tenant)
            .bind(input.registration)
            .bind(input.generation as i64)
            .bind(input.sequence as i64)
            .bind(input.operation)
            .bind(&body)
            .execute(&mut *c)
            .await
            .map_err(db)?
            .rows_affected();
    if inserted == 1 {
        return Ok(false);
    }
    let previous: Option<serde_json::Value> =
        sqlx::query_scalar(crate::storage_profile::sql(profile, usage).observations_record_in_2)
            .bind(tenant)
            .bind(input.operation)
            .fetch_optional(c)
            .await
            .map_err(db)?;
    if previous.as_ref() != Some(&body) {
        return Err(Error::Conflict);
    }
    Ok(true)
}
/// Only the current registration generation is eligible; device clock never orders reports.
pub async fn latest_in(
    profile: rss_mdm_install_support::StorageProfile,
    usage: crate::Use,
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Option<ObservedInstallation>, Error> {
    let tenant_id = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
    let consumers = rss_mdm_registration_service::device::consumers_for_device_in(
        profile,
        c,
        tenant_id,
        usage,
        Some(device),
    )
    .await?;
    let Some((registration, generation)) = consumers.first() else {
        return Ok(None);
    };
    let row: Option<(serde_json::Value, i64)> =
        sqlx::query_as(crate::storage_profile::sql(profile, usage).observations_latest_in_1)
            .bind(tenant)
            .bind(registration)
            .bind(generation)
            .fetch_optional(c)
            .await
            .map_err(db)?;
    row.map(|(body, received_at)| {
        Ok(ObservedInstallation {
            observation: serde_json::from_value(body).map_err(|_| Error::Conflict)?,
            received_at,
        })
    })
    .transpose()
}
