//! WinDC uses the main MDM device and a purpose-bound enrollment request.
//! ref: Microsoft declared-configuration-enrollment; sqlx src/transaction.rs.
use super::*;
use crate::database::db;
use sqlx::Row;

/// Freeze the main device and its current credential in a protocol request.
pub async fn request_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    parent: &DevicePrincipal,
    id: Uuid,
    operation: Uuid,
) -> Result<(), Error> {
    if profile != parent.profile()
        || parent.purpose() != Purpose::Primary
        || parent.channel() != Some(Channel::Mdm)
        || id.is_nil()
        || operation.is_nil()
    {
        return Err(Error::Forbidden);
    }
    let tenant = parent.tenant().to_string();
    crate::lifecycle::require_work_in(profile, c, &tenant, parent.device()).await?;
    store::revalidate_management(profile, c, parent).await?;
    let windows_profile: String =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_linked_request_in_1)
            .bind(&tenant)
            .bind(parent.device().into_uuid())
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_linked_request_in_3)
        .bind(tenant)
        .bind(id)
        .bind(parent.device().into_uuid())
        .bind(parent.credential())
        .bind(operation)
        .bind(windows_profile)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
/// Bind the protocol credential to its original request; no device is allocated here.
pub async fn bind_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    parent: &DevicePrincipal,
    credential: &VerifiedChannelCredential,
    request: Uuid,
    ids: [Uuid; 2],
) -> Result<RegistrationReceipt, Error> {
    if profile != credential.profile
        || profile != parent.profile()
        || parent.purpose() != Purpose::Primary
        || credential.tenant != parent.tenant()
        || credential.purpose != Purpose::WindowsDeclared
        || credential.source != ReportSource::MdmWindows
    {
        return Err(Error::Forbidden);
    }
    let tenant = parent.tenant().to_string();
    crate::lifecycle::require_work_in(profile, c, &tenant, parent.device()).await?;
    store::revalidate_management(profile, c, parent).await?;
    let row = sqlx::query(crate::storage_profile::sql(profile).device_linked_bind_in_1)
        .bind(&tenant)
        .bind(request)
        .bind(parent.device().into_uuid())
        .bind(parent.credential())
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    let prior: Vec<Uuid> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_linked_prior_credentials)
            .bind(&tenant)
            .bind(parent.device().into_uuid())
            .bind(request)
            .fetch_all(&mut *c)
            .await
            .map_err(db)?;
    for old in prior {
        rss_mdm_pki_service::certificates::revoke_credential_in(profile, c, &tenant, old)
            .await
            .map_err(|_| Error::Storage)?;
    }
    // Supersede only earlier WinDC contexts. The main registration and its work survive.
    sqlx::query(crate::storage_profile::sql(profile).device_linked_bind_in_3)
        .bind(&tenant)
        .bind(parent.device().into_uuid())
        .bind(request)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    let locator: String = credential
        .locator
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    sqlx::query(crate::storage_profile::sql(profile).device_linked_bind_in_5)
        .bind(&tenant)
        .bind(ids[0])
        .bind(parent.device().into_uuid())
        .bind(locator)
        .bind(request)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_linked_bind_in_6)
        .bind(&tenant)
        .bind(request)
        .bind(ids[1])
        .execute(&mut *c)
        .await
        .map_err(db)?;
    Ok(RegistrationReceipt {
        operation_id: row.try_get("issuance_operation").map_err(db)?,
        request_id: request,
        device: *parent.device(),
        channel: Channel::Mdm,
        credential: ids[0],
        epoch: ids[1],
    })
}
/// Publish readiness only after a real authenticated SyncML exchange.
pub async fn ready_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
) -> Result<bool, Error> {
    if profile != p.profile() {
        return Err(Error::Forbidden);
    }
    store::revalidate_management(profile, c, p).await?;
    let Some(request) = p.protocol_request() else {
        return Ok(false);
    };
    Ok(
        sqlx::query(crate::storage_profile::sql(profile).device_linked_ready_in_1)
            .bind(p.tenant().to_string())
            .bind(p.device().into_uuid())
            .bind(request)
            .execute(c)
            .await
            .map_err(db)?
            .rows_affected()
            == 1,
    )
}

/// End only the authenticated WinDC request; the primary device and business work survive.
pub async fn revoke_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
) -> Result<(), Error> {
    if p.purpose() != Purpose::WindowsDeclared || profile != p.profile() {
        return Err(Error::Forbidden);
    }
    let request = p.protocol_request().ok_or(Error::Unauthorized)?;
    store::revalidate_management(profile, c, p).await?;
    let tenant = p.tenant().to_string();
    let credentials: Vec<Uuid> =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_linked_revoke_credentials)
            .bind(&tenant)
            .bind(p.device().into_uuid())
            .bind(request)
            .fetch_all(&mut *c)
            .await
            .map_err(db)?;
    for credential in credentials {
        rss_mdm_pki_service::certificates::revoke_credential_in(profile, c, &tenant, credential)
            .await
            .map_err(|_| Error::Storage)?;
    }
    sqlx::query(crate::storage_profile::sql(profile).device_linked_revoke_state)
        .bind(tenant)
        .bind(p.device().into_uuid())
        .bind(request)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
