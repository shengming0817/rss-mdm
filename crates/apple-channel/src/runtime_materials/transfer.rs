//! 一次性离线转交；运行服务不读取旧文件，也不能覆盖已存在的材料版本。
use super::*;
use rss_mdm_native_protection::Protector;
use sqlx::{PgConnection, Row};
pub enum PrivateKey<'a> {
    Pem(&'a str),
    Pkcs8(&'a [u8]),
}
pub struct Material<'a> {
    pub purpose: Purpose,
    pub revision: i64,
    pub key_id: Uuid,
    pub private_key: PrivateKey<'a>,
    pub certificate_chain_pem: &'a str,
    pub expected_topic: Option<&'a str>,
    pub account_alias: Option<&'a str>,
}
pub async fn import(
    c: &mut PgConnection,
    tenant: &str,
    material: Material<'_>,
    roots: &[Vec<u8>],
    now: i64,
    protection: &Protector,
) -> Result<PublicVersion, Error> {
    let operator: bool =
        sqlx::query_scalar("SELECT current_user='mdm_owner' AND session_user='mdm_owner'")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    if !operator || material.key_id.is_nil() || material.revision <= 0 {
        return Err(Error::Forbidden);
    }
    let pem = match material.private_key {
        PrivateKey::Pem(value) => Zeroizing::new(value.as_bytes().to_vec()),
        PrivateKey::Pkcs8(value) => {
            if value.len() > 32768 {
                return Err(Error::Malformed);
            }
            Zeroizing::new(
                openssl::pkey::PKey::private_key_from_pkcs8(value)
                    .and_then(|key| key.private_key_to_pem_pkcs8())
                    .map_err(|_| Error::CertificateRequest)?,
            )
        }
    };
    let key = crypto::prepare(
        tenant,
        material.purpose,
        Some(std::str::from_utf8(&pem).map_err(|_| Error::CertificateRequest)?),
    )?;
    let certificate = crypto::certificate(
        material.purpose,
        material.certificate_chain_pem,
        &key.private,
        roots,
        now,
    )?;
    if certificate.topic.as_deref() != material.expected_topic {
        return Err(Error::Conflict);
    }
    storage::lock(c, tenant, material.purpose).await?;
    let existing=sqlx::query("SELECT key_id,public_digest,certificate_digest,private_key FROM mdm_apple_runtime.versions WHERE tenant_id=$1::uuid AND purpose=$2 AND revision=$3").bind(tenant).bind(material.purpose.name()).bind(material.revision).fetch_optional(&mut *c).await.map_err(db)?;
    if let Some(row) = existing {
        let id: Uuid = row.try_get("key_id").map_err(db)?;
        let public: String = row.try_get("public_digest").map_err(db)?;
        let digest: Option<String> = row.try_get("certificate_digest").map_err(db)?;
        if id != material.key_id
            || public != key.public_digest
            || digest.as_deref() != Some(certificate.digest.as_str())
        {
            return Err(Error::Conflict);
        }
        let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
        let original = protection
            .open_bytes(
                &sealed,
                &aad(tenant, material.purpose, material.revision, id)?,
            )
            .map_err(|_| Error::Conflict)?;
        if original.expose() != key.private.as_slice() {
            return Err(Error::Conflict);
        }
    } else {
        // 只允许追加精确旧材料；同一目的已有不同来源的运行版本时拒绝接管。
        let foreign:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple_runtime.versions WHERE tenant_id=$1::uuid AND purpose=$2 AND revision>=$3)").bind(tenant).bind(material.purpose.name()).bind(material.revision).fetch_one(&mut *c).await.map_err(db)?;
        if foreign {
            return Err(Error::Conflict);
        }
        storage::insert(
            c,
            protection,
            tenant,
            material.purpose,
            material.revision,
            material.key_id,
            &key,
            Some((material.certificate_chain_pem, &certificate)),
        )
        .await?;
        storage::select(c, tenant, material.purpose, material.revision).await?;
    }
    if material.purpose == Purpose::ManagedAccount {
        let alias = material.account_alias.ok_or(Error::Malformed)?;
        let original:Option<i64>=sqlx::query_scalar("SELECT revision FROM mdm_apple_runtime.account_bindings WHERE tenant_id=$1::uuid AND alias=$2").bind(tenant).bind(alias).fetch_optional(&mut *c).await.map_err(db)?;
        if original.is_some_and(|revision| revision != material.revision) {
            return Err(Error::Conflict);
        }
        storage::bind_account(c, tenant, alias, material.revision).await?;
    }
    storage::version(c, tenant, material.purpose, material.revision).await
}
