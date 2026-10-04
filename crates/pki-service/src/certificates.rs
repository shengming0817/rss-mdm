//! Certificate mappings and physical revocation work share the original lifecycle transaction.
use crate::Error;
use rss_mdm_device_trust::serial;
use uuid::Uuid;
use x509_cert::der::Decode;
pub async fn record_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    purpose: &str,
    registration: Uuid,
    issuer: &str,
    certificate: &[u8],
) -> Result<(), Error> {
    record_candidate_in(c, tenant, purpose, Some(registration), issuer, certificate).await
}
/// Issued candidates are mapped before activation; a registration can be attached once.
pub async fn record_candidate_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    purpose: &str,
    registration: Option<Uuid>,
    issuer: &str,
    certificate: &[u8],
) -> Result<(), Error> {
    let leaf = x509_cert::Certificate::from_der(certificate).map_err(|_| Error::Request)?;
    let fingerprint = sha2::Sha256::digest(certificate).to_vec();
    let serial = serial(leaf.tbs_certificate.serial_number.as_bytes());
    let end = leaf
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;
    let changed = sqlx::query("INSERT INTO mdm_pki.certificates(tenant_id,purpose,fingerprint,issuer,serial,registration,not_after,certificate) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,purpose,fingerprint) DO NOTHING")
        .bind(tenant).bind(purpose).bind(&fingerprint).bind(issuer).bind(&serial).bind(registration)
        .bind(end).bind(certificate).execute(&mut *c).await.map_err(|_| Error::Storage)?.rows_affected();
    if changed == 0 {
        let old: (Option<Uuid>,Vec<u8>,String) = sqlx::query_as("SELECT registration,certificate,issuer FROM mdm_pki.certificates WHERE tenant_id=$1::uuid AND purpose=$2 AND fingerprint=$3")
            .bind(tenant).bind(purpose).bind(fingerprint).fetch_one(&mut *c).await.map_err(|_| Error::Storage)?;
        if (old.0.is_some() && registration.is_some() && old.0 != registration)
            || old.1 != certificate
            || old.2 != issuer
        {
            return Err(Error::Conflict);
        }
    }
    if registration.is_some() {
        sqlx::query("UPDATE mdm_pki.certificates SET registration=$4 WHERE tenant_id=$1::uuid AND purpose=$2 AND fingerprint=$3 AND registration IS NULL")
            .bind(tenant).bind(purpose).bind(sha2::Sha256::digest(certificate).to_vec()).bind(registration).execute(c).await.map_err(|_|Error::Storage)?;
    }
    Ok(())
}
pub async fn revoke_registration_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registration: Uuid,
) -> Result<(), Error> {
    let rows: Vec<(String,String,String)> = sqlx::query_as("SELECT purpose,issuer,serial FROM mdm_pki.certificates WHERE tenant_id=$1::uuid AND registration=$2 AND not_after>floor(extract(epoch FROM clock_timestamp()))::bigint")
        .bind(tenant).bind(registration).fetch_all(&mut *c).await.map_err(|_| Error::Storage)?;
    for (purpose, issuer, serial) in rows {
        enqueue_in(c, tenant, &purpose, &issuer, &serial).await?;
    }
    Ok(())
}
pub async fn enqueue_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    purpose: &str,
    issuer: &str,
    serial: &str,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_pki.revocations(tenant_id,purpose,issuer,serial,attempt,state) VALUES($1::uuid,$2,$3,$4,$5,'pending') ON CONFLICT(tenant_id,purpose,issuer,serial) DO NOTHING")
        .bind(tenant).bind(purpose).bind(issuer).bind(serial).bind(Uuid::new_v4()).execute(c).await.map_err(|_| Error::Storage)?;
    Ok(())
}
/// Retiring a current credential queues its actual certificate in the original owner transaction.
pub async fn revoke_credential_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    credential: Uuid,
) -> Result<(), Error> {
    let rows:Vec<(String,String,String)>=sqlx::query_as("SELECT cert.purpose,cert.issuer,cert.serial FROM mdm_pki.certificates cert JOIN mdm_access.credentials k ON k.tenant_id=cert.tenant_id AND k.registration=cert.registration AND k.locator=encode(cert.fingerprint,'hex') WHERE k.tenant_id=$1::uuid AND k.id=$2 AND cert.not_after>floor(extract(epoch FROM clock_timestamp()))::bigint")
        .bind(tenant).bind(credential).fetch_all(&mut *c).await.map_err(|_|Error::Storage)?;
    for (purpose, issuer, serial) in rows {
        enqueue_in(c, tenant, &purpose, &issuer, &serial).await?;
    }
    Ok(())
}
use sha2::Digest;

/// A known unactivated candidate is physically revoked when its grant is revoked.
pub async fn revoke_attempt_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    attempt: Uuid,
) -> Result<(), Error> {
    let record:Option<(String,String,Vec<u8>)>=sqlx::query_as("SELECT purpose,issuer,chain FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2 AND state='issued'")
        .bind(tenant).bind(attempt).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)?;
    if let Some((purpose, issuer, bytes)) = record {
        let chain: Vec<Vec<u8>> = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
        let certificate = x509_cert::Certificate::from_der(chain.first().ok_or(Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        enqueue_in(
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
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registration: Uuid,
    purpose: rss_mdm_agent_wire::pki::Purpose,
    now: i64,
) -> Result<bool, Error> {
    use sqlx::Row;
    let row = sqlx::query("SELECT cert.certificate,trust.body,EXISTS(SELECT 1 FROM mdm_pki.revocations v WHERE v.tenant_id=cert.tenant_id AND v.purpose=cert.purpose AND v.issuer=cert.issuer AND v.serial=cert.serial) AS revoked FROM mdm_pki.certificates cert JOIN mdm_access.credentials k ON k.tenant_id=cert.tenant_id AND k.registration=cert.registration AND k.locator=encode(cert.fingerprint,'hex') JOIN mdm_pki.trust trust ON trust.tenant_id=cert.tenant_id AND trust.purpose=cert.purpose WHERE cert.tenant_id=$1::uuid AND cert.registration=$2 AND cert.purpose=$3 AND k.state='active' ORDER BY k.id LIMIT 2")
        .bind(tenant).bind(registration).bind(crate::registry::purpose(purpose)).fetch_all(c).await.map_err(|_|Error::Storage)?;
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
