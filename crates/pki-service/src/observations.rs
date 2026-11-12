//! Dedicated pki observations. No observation writes rotation acknowledgements.
//! ref: sqlx v0.8.6 sqlx-postgres/src/transaction.rs (caller-owned transaction).
use crate::Error;
use rss_mdm_agent_wire::pki::{Observation, ObservedInstallation};
use sqlx::PgConnection;
pub const fn install_sql(profile: rss_mdm_install_support::StorageProfile) -> &'static str {
    crate::storage_profile::sql(profile).observations
}
fn db(_: sqlx::Error) -> Error {
    Error::Storage
}
/// Persist a report in the authenticated owner's transaction. Exact replay retains receipt time.
pub async fn record_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    input: &Observation,
) -> Result<bool, Error> {
    input.validate().map_err(|_| Error::Conflict)?;
    let body = serde_json::to_value(input).map_err(|_| Error::Conflict)?;
    let inserted = sqlx::query(crate::storage_profile::sql(profile).observations_record_in_1)
        .bind(tenant)
        .bind(input.device_id.into_uuid())
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
        sqlx::query_scalar(crate::storage_profile::sql(profile).observations_record_in_2)
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
/// Only the active device is eligible; device clock never orders reports.
pub async fn latest_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Option<ObservedInstallation>, Error> {
    let row: Option<(serde_json::Value, i64)> =
        sqlx::query_as(crate::storage_profile::sql(profile).observations_latest_in_1)
            .bind(tenant)
            .bind(device.into_uuid())
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

impl crate::registry::Registry {
    pub async fn agent_trust_observation(
        &self,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
    ) -> Result<Option<ObservedInstallation>, Error> {
        let profile = self.profile();

        p.require(
            rss_mdm_authorization_service::Permission::InventoryRead,
            Some(device),
        )
        .map_err(|_| Error::Forbidden)?;
        if self
            .trust(rss_mdm_agent_wire::pki::Purpose::Agent)?
            .tenant
            .to_string()
            != p.tenant_id()
        {
            return Err(Error::Forbidden);
        }
        let mut tx = self.begin(p.tenant_id()).await?;
        let value = latest_in(profile, &mut tx, p.tenant_id(), device).await?;
        p.check_live().map_err(|_| Error::Forbidden)?;
        tx.rollback().await.map_err(db)?;
        Ok(value)
    }
}
