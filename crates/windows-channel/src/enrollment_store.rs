//! Persisted enrollment intent and certificate state; protocol signing remains with Windows.
pub async fn intent(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
) -> Result<Option<sqlx::postgres::PgRow>, sqlx::Error> {
    sqlx::query("SELECT q.windows_profile AS enrollment_type,i.csr,i.tbs,i.issuer,i.configuration,i.registration::text,i.credential::text,i.epoch::text,i.secrets FROM mdm_access.enrollment_intents i JOIN mdm_access.requests q ON (q.tenant_id,q.id)=(i.tenant_id,i.request_id) WHERE i.tenant_id=$1::uuid AND i.request_id=$2::uuid")
            .bind(tenant).bind(request).fetch_optional(c).await
}
pub struct NewIntent<'a> {
    pub request: String,
    pub csr: &'a [u8],
    pub tbs: &'a [u8],
    pub issuer: &'a [u8],
    pub configuration: &'a str,
    pub registration: String,
    pub credential: String,
    pub epoch: String,
    pub secrets: &'a [u8],
}
pub async fn insert_intent(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    intent: NewIntent<'_>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let NewIntent {
        request,
        csr,
        tbs,
        issuer,
        configuration,
        registration,
        credential,
        epoch,
        secrets,
    } = intent;
    sqlx::query("INSERT INTO mdm_access.enrollment_intents(tenant_id,request_id,csr,tbs,issuer,configuration,registration,credential,epoch,secrets) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7::uuid,$8::uuid,$9::uuid,$10)")
            .bind(tenant).bind(request).bind(csr).bind(tbs).bind(issuer).bind(configuration).bind(registration).bind(credential).bind(epoch).bind(secrets)
            .execute(c).await
}
pub async fn certificate(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar("SELECT certificate FROM mdm_access.enrollment_certificates WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
            .bind(tenant).bind(request).fetch_optional(c).await
}
pub async fn required_certificate(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
) -> Result<Vec<u8>, sqlx::Error> {
    sqlx::query_scalar("SELECT certificate FROM mdm_access.enrollment_certificates WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
                .bind(tenant).bind(request).fetch_one(c).await
}
pub async fn insert_certificate(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
    certificate: &[u8],
    nonce: &[u8],
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query("INSERT INTO mdm_access.enrollment_certificates(tenant_id,request_id,certificate,server_nonce) VALUES($1::uuid,$2::uuid,$3,$4)")
            .bind(tenant).bind(request).bind(certificate).bind(nonce).execute(c).await
}
pub async fn registration(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    registration: &str,
) -> Result<sqlx::postgres::PgRow, sqlx::Error> {
    sqlx::query("SELECT i.request_id::text,i.secrets,c.server_nonce FROM mdm_access.enrollment_intents i JOIN mdm_access.enrollment_certificates c ON (c.tenant_id,c.request_id)=(i.tenant_id,i.request_id) WHERE i.tenant_id=$1::uuid AND i.registration=$2::uuid FOR UPDATE OF c")
            .bind(tenant).bind(registration).fetch_one(c).await
}
pub async fn update_nonce(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    request: String,
    nonce: &[u8],
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query("UPDATE mdm_access.enrollment_certificates SET server_nonce=$3 WHERE tenant_id=$1::uuid AND request_id=$2::uuid")
                .bind(tenant).bind(request).bind(nonce).execute(c).await
}

use crate::{Error, database::db};
use sqlx::Row;
use uuid::Uuid;

pub async fn active_windows_enrollment(
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<Uuid, Error> {
    let registration = crate::enrollment::store::active_registration(tx, tenant, id).await?;
    if !crate::device::store::active_source_in(
        tx,
        tenant,
        registration,
        rss_mdm_inventory::ReportSource::MdmWindows,
    )
    .await?
    {
        return Err(Error::Conflict);
    }
    let row=sqlx::query("SELECT certificate,floor(extract(epoch FROM clock_timestamp()))::bigint AS now FROM mdm_access.enrollment_certificates WHERE tenant_id=$1::uuid AND request_id=$2::uuid").bind(tenant).bind(id.to_string()).fetch_one(tx).await.map_err(db)?;
    use x509_cert::der::Decode;
    let certificate: Vec<u8> = row.try_get("certificate").map_err(db)?;
    let certificate =
        x509_cert::Certificate::from_der(&certificate).map_err(|_| Error::Conflict)?;
    rss_mdm_certificate::windows::leaf_usage(
        &certificate.tbs_certificate,
        row.try_get("now").map_err(db)?,
    )?;
    Ok(registration)
}
