use super::*;
use sqlx::{PgConnection, Row};
pub(super) async fn lock(
    c: &mut PgConnection,
    tenant: &str,
    purpose: Purpose,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_apple_runtime.heads(tenant_id,purpose) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(tenant).bind(purpose.name()).execute(&mut *c).await.map_err(db)?;
    sqlx::query("SELECT revision FROM mdm_apple_runtime.heads WHERE tenant_id=$1::uuid AND purpose=$2 FOR UPDATE").bind(tenant).bind(purpose.name()).fetch_one(c).await.map_err(db)?;
    Ok(())
}
pub(super) async fn head(
    c: &mut PgConnection,
    tenant: &str,
    purpose: Purpose,
) -> Result<(i64, Option<i64>), Error> {
    Ok(sqlx::query_as("SELECT revision,desired_revision FROM mdm_apple_runtime.heads WHERE tenant_id=$1::uuid AND purpose=$2")
        .bind(tenant).bind(purpose.name()).fetch_optional(c).await.map_err(db)?.unwrap_or((0,None)))
}
fn decode(r: &sqlx::postgres::PgRow) -> Result<PublicVersion, Error> {
    Ok(PublicVersion {
        revision: r.try_get("revision").map_err(db)?,
        key_id: r.try_get("key_id").map_err(db)?,
        public_key_digest: r.try_get("public_digest").map_err(db)?,
        csr: r.try_get("csr").map_err(db)?,
        certificate_chain_pem: r.try_get("certificate").map_err(db)?,
        certificate_digest: r.try_get("certificate_digest").map_err(db)?,
        topic: r.try_get("topic").map_err(db)?,
        expires_at: r.try_get("expires_at").map_err(db)?,
        revoked: r.try_get("revoked").map_err(db)?,
    })
}
pub(super) async fn version(
    c: &mut PgConnection,
    tenant: &str,
    purpose: Purpose,
    revision: i64,
) -> Result<PublicVersion, Error> {
    let r=sqlx::query("SELECT revision,key_id,public_digest,csr,certificate,certificate_digest,topic,expires_at,revoked FROM mdm_apple_runtime.versions WHERE tenant_id=$1::uuid AND purpose=$2 AND revision=$3")
        .bind(tenant).bind(purpose.name()).bind(revision).fetch_optional(c).await.map_err(db)?.ok_or(Error::NotFound)?;
    decode(&r)
}
pub(super) async fn versions(
    c: &mut PgConnection,
    tenant: &str,
    purpose: Purpose,
) -> Result<Vec<PublicVersion>, Error> {
    let rows=sqlx::query("SELECT revision,key_id,public_digest,csr,certificate,certificate_digest,topic,expires_at,revoked FROM mdm_apple_runtime.versions WHERE tenant_id=$1::uuid AND purpose=$2 ORDER BY revision DESC LIMIT 65")
        .bind(tenant).bind(purpose.name()).fetch_all(c).await.map_err(db)?;
    if rows.len() > 64 {
        return Err(Error::Conflict);
    }
    rows.iter().map(decode).collect()
}
pub(super) async fn material(
    c: &mut PgConnection,
    app: &HttpState,
    tenant: &str,
    purpose: Purpose,
    revision: i64,
) -> Result<(PublicVersion, rss_mdm_native_protection::Plaintext), Error> {
    let r=sqlx::query("SELECT * FROM mdm_apple_runtime.versions WHERE tenant_id=$1::uuid AND purpose=$2 AND revision=$3").bind(tenant).bind(purpose.name()).bind(revision).fetch_optional(c).await.map_err(db)?.ok_or(Error::NotFound)?;
    let public = decode(&r)?;
    if public.revoked {
        return Err(Error::Conflict);
    }
    let sealed: Vec<u8> = r.try_get("private_key").map_err(db)?;
    let private = app
        .protection
        .open_bytes(&sealed, &aad(tenant, purpose, revision, public.key_id)?)
        .map_err(|_| Error::Conflict)?;
    Ok((public, private))
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn insert(
    c: &mut PgConnection,
    app: &HttpState,
    tenant: &str,
    purpose: Purpose,
    revision: i64,
    key_id: Uuid,
    key: &crypto::Key,
    certificate: Option<(&str, &crypto::Certificate)>,
) -> Result<(), Error> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_apple_runtime.versions WHERE tenant_id=$1::uuid AND purpose=$2",
    )
    .bind(tenant)
    .bind(purpose.name())
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if count >= 64 {
        return Err(Error::Conflict);
    }
    let sealed = app
        .protection
        .seal_bytes(&key.private, &aad(tenant, purpose, revision, key_id)?)
        .map_err(|_| Error::Conflict)?;
    sqlx::query("INSERT INTO mdm_apple_runtime.versions(tenant_id,purpose,revision,key_id,public_digest,private_key,csr,certificate,certificate_digest,topic,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(tenant).bind(purpose.name()).bind(revision).bind(key_id).bind(&key.public_digest).bind(sealed).bind(&key.csr)
        .bind(certificate.map(|v|v.0)).bind(certificate.map(|v|v.1.digest.as_str())).bind(certificate.and_then(|v|v.1.topic.as_deref())).bind(certificate.map(|v|v.1.expires))
        .execute(&mut *c).await.map_err(db)?;
    sqlx::query(
        "UPDATE mdm_apple_runtime.heads SET revision=$3 WHERE tenant_id=$1::uuid AND purpose=$2",
    )
    .bind(tenant)
    .bind(purpose.name())
    .bind(revision)
    .execute(c)
    .await
    .map_err(db)?;
    Ok(())
}
pub(super) async fn select(
    c: &mut PgConnection,
    tenant: &str,
    purpose: Purpose,
    revision: i64,
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_apple_runtime.versions SET selected=true WHERE tenant_id=$1::uuid AND purpose=$2 AND revision=$3 AND NOT revoked AND certificate IS NOT NULL")
        .bind(tenant).bind(purpose.name()).bind(revision).execute(&mut *c).await.map_err(db)?;
    sqlx::query("UPDATE mdm_apple_runtime.heads SET desired_revision=$3,revision=revision+1 WHERE tenant_id=$1::uuid AND purpose=$2").bind(tenant).bind(purpose.name()).bind(revision).execute(c).await.map_err(db)?;
    Ok(())
}
pub(super) async fn replay(
    c: &mut PgConnection,
    app: &HttpState,
    tenant: &str,
    id: Uuid,
    request: &[u8],
) -> Result<Option<(Value, [u8; 32])>, Error> {
    let row=sqlx::query("SELECT fingerprint_key,fingerprint,receipt FROM mdm_apple_runtime.operations WHERE tenant_id=$1::uuid AND operation_id=$2")
        .bind(tenant).bind(id).fetch_optional(c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let key: String = row.try_get("fingerprint_key").map_err(db)?;
    let digest: Vec<u8> = row.try_get("fingerprint").map_err(db)?;
    app.protection
        .verify_mac_with_key(&key, request, &request_aad(tenant, id)?, &digest)
        .map_err(|_| Error::Conflict)?;
    let original: [u8; 32] = digest.try_into().map_err(|_| Error::Conflict)?;
    Ok(Some((row.try_get("receipt").map_err(db)?, original)))
}
pub(super) async fn save(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
    key: &str,
    digest: &[u8],
    receipt: &Value,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_apple_runtime.operations(tenant_id,operation_id,fingerprint_key,fingerprint,receipt) VALUES($1::uuid,$2,$3,$4,$5)")
        .bind(tenant).bind(id).bind(key).bind(digest).bind(receipt).execute(c).await.map_err(db)?;
    Ok(())
}
pub(super) async fn receipt(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
) -> Result<Option<Value>, Error> {
    sqlx::query_scalar("SELECT receipt FROM mdm_apple_runtime.operations WHERE tenant_id=$1::uuid AND operation_id=$2").bind(tenant).bind(id).fetch_optional(c).await.map_err(db)
}
