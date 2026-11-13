//! Certificate mappings and physical revocation work share the original lifecycle transaction.
use crate::Error;
use rss_mdm_device_trust::serial;
use uuid::Uuid;
use x509_cert::der::Decode;
pub async fn record_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    purpose: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    issuer: &str,
    certificate: &[u8],
) -> Result<(), Error> {
    record_candidate_in(
        profile,
        c,
        tenant,
        purpose,
        Some(device),
        issuer,
        certificate,
    )
    .await
}
/// Issued candidates are mapped before activation; a device can be attached once.
pub async fn record_candidate_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    purpose: &str,
    device: Option<&rss_mdm_agent_wire::DeviceId>,
    issuer: &str,
    certificate: &[u8],
) -> Result<(), Error> {
    let qualification =
        crate::qualification::for_certificate_in(profile, c, tenant, purpose, certificate).await?;
    let leaf = x509_cert::Certificate::from_der(certificate).map_err(|_| Error::Request)?;
    let fingerprint = sha2::Sha256::digest(certificate).to_vec();
    let serial = serial(leaf.tbs_certificate.serial_number.as_bytes());
    let end = leaf
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;
    let changed =
        sqlx::query(crate::storage_profile::sql(profile).certificates_record_candidate_in_1)
            .bind(tenant)
            .bind(purpose)
            .bind(&fingerprint)
            .bind(issuer)
            .bind(&serial)
            .bind(device.map(|id| id.into_uuid()))
            .bind(end)
            .bind(certificate)
            .bind(rss_mdm_device_trust::qualification::VERSION)
            .bind(&qualification.trust)
            .bind(qualification.start)
            .bind(qualification.end)
            .execute(&mut *c)
            .await
            .map_err(|_| Error::Storage)?
            .rows_affected();
    if changed == 0 {
        let old: (Option<Uuid>, Vec<u8>, String, bool) =
            sqlx::query_as(crate::storage_profile::sql(profile).certificates_record_candidate_in_2)
                .bind(tenant)
                .bind(purpose)
                .bind(fingerprint)
                .bind(rss_mdm_device_trust::qualification::VERSION)
                .bind(&qualification.trust)
                .bind(qualification.start)
                .bind(qualification.end)
                .fetch_one(&mut *c)
                .await
                .map_err(|_| Error::Storage)?;
        if (old.0.is_some() && device.is_some() && old.0 != device.map(|id| id.into_uuid()))
            || old.1 != certificate
            || old.2 != issuer
            || !old.3
        {
            return Err(Error::Conflict);
        }
    }
    if device.is_some() {
        sqlx::query(crate::storage_profile::sql(profile).certificates_record_candidate_in_3)
            .bind(tenant)
            .bind(purpose)
            .bind(sha2::Sha256::digest(certificate).to_vec())
            .bind(device.map(|id| id.into_uuid()))
            .execute(c)
            .await
            .map_err(|_| Error::Storage)?;
    }
    Ok(())
}
pub async fn revoke_registration_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<(), Error> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as(crate::storage_profile::sql(profile).certificates_revoke_registration_in_1)
            .bind(tenant)
            .bind(device.into_uuid())
            .fetch_all(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    for (purpose, issuer, serial) in rows {
        enqueue_in(profile, c, tenant, &purpose, &issuer, &serial).await?;
    }
    Ok(())
}
pub async fn enqueue_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    purpose: &str,
    issuer: &str,
    serial: &str,
) -> Result<(), Error> {
    sqlx::query(crate::storage_profile::sql(profile).certificates_enqueue_in_1)
        .bind(tenant)
        .bind(purpose)
        .bind(issuer)
        .bind(serial)
        .bind(Uuid::new_v4())
        .execute(c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(())
}
/// Retiring a current credential queues its actual certificate in the original owner transaction.
pub async fn revoke_credential_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    credential: Uuid,
) -> Result<(), Error> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as(crate::storage_profile::sql(profile).certificates_revoke_credential_in_1)
            .bind(tenant)
            .bind(credential)
            .fetch_all(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    for (purpose, issuer, serial) in rows {
        enqueue_in(profile, c, tenant, &purpose, &issuer, &serial).await?;
    }
    Ok(())
}
use sha2::Digest;

/// A known unactivated candidate is physically revoked when its grant is revoked.
pub async fn revoke_attempt_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    attempt: Uuid,
) -> Result<(), Error> {
    let record: Option<(String, String, Vec<u8>)> =
        sqlx::query_as(crate::storage_profile::sql(profile).certificates_revoke_attempt_in_1)
            .bind(tenant)
            .bind(attempt)
            .fetch_optional(&mut *c)
            .await
            .map_err(|_| Error::Storage)?;
    if let Some((purpose, issuer, bytes)) = record {
        let chain: Vec<Vec<u8>> = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
        let certificate = x509_cert::Certificate::from_der(chain.first().ok_or(Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        enqueue_in(
            profile,
            c,
            tenant,
            &purpose,
            &issuer,
            &serial(certificate.tbs_certificate.serial_number.as_bytes()),
        )
        .await?;
    }
    Ok(())
}

/// Reads the current native credential and its persisted trust in one product snapshot.
/// Retired credentials and queued revocations never advertise management availability.
pub async fn current_native_credential_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    purpose: rss_mdm_agent_wire::pki::Purpose,
    now: i64,
) -> Result<bool, Error> {
    use sqlx::Row;
    let row = sqlx::query(
        crate::storage_profile::sql(profile).certificates_current_native_credential_in_1,
    )
    .bind(tenant)
    .bind(device.into_uuid())
    .bind(crate::registry::purpose(purpose))
    .fetch_all(c)
    .await
    .map_err(|_| Error::Storage)?;
    if row.len() > 1 {
        return Err(Error::Conflict);
    }
    let Some(row) = row.first() else {
        return Ok(false);
    };
    if row
        .try_get::<bool, _>("revoked")
        .map_err(|_| Error::Storage)?
    {
        return Ok(false);
    }
    let body: Vec<u8> = row.try_get("body").map_err(|_| Error::Storage)?;
    let trust: rss_mdm_agent_wire::pki::Trust =
        serde_json::from_slice(&body).map_err(|_| Error::Storage)?;
    if trust.tenant.to_string() != tenant || trust.purpose != purpose {
        return Err(Error::Storage);
    }
    let certificate: Vec<u8> = row.try_get("certificate").map_err(|_| Error::Storage)?;
    let trust = match rss_mdm_device_trust::DeviceTrust::restore(trust, purpose, now) {
        Ok(trust) => trust,
        Err(rss_mdm_device_trust::Error::Expired) => return Ok(false),
        Err(_) => return Err(Error::Storage),
    };
    // verify() uses the same purpose/issuer/CRL/time checks as real native authentication.
    Ok(trust.verify(&[certificate.into()], now).is_ok())
}
