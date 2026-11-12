//! The protected registration state of one device, including inactive history.
use crate::{Error, Store, database::db};
use rss_mdm_authorization_service::Permission;

pub async fn read(
    profile: rss_mdm_install_support::StorageProfile,
    database: &Store,
    request: &rss_mdm_authorization_service::context::RequestAuth,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Registration, Error> {
    let proof = request.proof.as_ref();
    if profile != proof.profile() || profile != database.profile() {
        return Err(Error::Forbidden);
    }

    proof.credentials(device)?;
    let mut tx = database.snapshot(proof.tenant_id()).await?;
    let current = rss_mdm_authorization_service::snapshot_on(
        proof.authority_profile(),
        &mut tx,
        proof.tenant_id(),
        proof.instance_id(),
    )
    .await?;
    current
        .require(proof, Permission::Credentials, Some(device))
        .map_err(rss_mdm_authorization_service::Error::from)?;
    let binding = current.query_binding(proof)?;
    let row: serde_json::Value =
        sqlx::query_scalar(crate::storage_profile::sql(profile).enrollment_registration_read)
            .bind(proof.tenant_id())
            .bind(device.into_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(Error::NotFound)?;
    let result = serde_json::from_value(row).map_err(|_| Error::Corrupt)?;
    proof.check_live()?;
    tx.rollback().await.map_err(db)?;
    database.confirm_query(request, &binding).await?;
    Ok(result)
}

#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub device_id: rss_mdm_agent_wire::DeviceId,
    pub source: Option<rss_mdm_inventory::ReportSource>,
    pub status: super::read::RegistrationState,
    pub enrolled_user: bool,
    pub enrollment_id: Option<uuid::Uuid>,
    pub certificate_grant_id: Option<uuid::Uuid>,
    pub windows_declared: Option<ProtocolContext>,
}

#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolContext {
    pub request_id: uuid::Uuid,
    pub ready: bool,
}
