//! Exact selected versions consumed by the host; no fallback to startup credential files.
use super::*;
use std::collections::BTreeMap;
/// Host-owned immutable application input. Values are material revisions, never filesystem paths.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub apns: i64,
    pub profile: i64,
    pub accounts: BTreeMap<String, i64>,
}
/// Verified material held only by the running owner. This type deliberately has no Debug/Serialize.
pub struct Loaded {
    pub profile: rss_mdm_certificate::apple::ProfileSigner,
    pub apns_certificate: Vec<u8>,
    pub apns_private_key: Zeroizing<Vec<u8>>,
    pub apns_topic: String,
    pub accounts: BTreeMap<String, rss_mdm_certificate::apple::ManagedAccountTokenSigner>,
}
#[allow(clippy::too_many_arguments)]
pub async fn load(
    store: &crate::Store,
    tenant: rss_request_context::TenantId,
    protection: &rss_mdm_native_protection::Protector,
    roots: &[Vec<u8>],
    selection: &Selection,
    now: i64,
) -> Result<Loaded, Error> {
    if selection.apns < 1 || selection.profile < 1 || selection.accounts.len() > 16 {
        return Err(Error::Malformed);
    }
    let tenant = tenant.to_string();
    let mut tx = store.material_snapshot(&tenant).await?;
    let apns = read(
        &mut tx,
        &tenant,
        protection,
        roots,
        Purpose::Apns,
        selection.apns,
        now,
    )
    .await?;
    let profile = read(
        &mut tx,
        &tenant,
        protection,
        roots,
        Purpose::Profile,
        selection.profile,
        now,
    )
    .await?;
    let profile = rss_mdm_certificate::apple::ProfileSigner::from_bytes(
        profile.0.as_bytes(),
        profile.1.expose(),
        now,
    )?;
    let mut accounts = BTreeMap::new();
    for (id, revision) in &selection.accounts {
        let row = storage::version(&mut tx, &tenant, Purpose::ManagedAccount, *revision).await?;
        if row.key_id.to_string() != *id {
            return Err(Error::Conflict);
        }
        let material = read(
            &mut tx,
            &tenant,
            protection,
            roots,
            Purpose::ManagedAccount,
            *revision,
            now,
        )
        .await?;
        accounts.insert(
            id.clone(),
            rss_mdm_certificate::apple::ManagedAccountTokenSigner::from_bytes(
                material.0.as_bytes(),
                material.1.expose(),
                now,
            )?,
        );
    }
    tx.rollback().await.map_err(db)?;
    let key = openssl::pkey::PKey::private_key_from_pkcs8(apns.1.expose())
        .map_err(|_| Error::CertificateRequest)?;
    Ok(Loaded {
        profile,
        apns_certificate: apns.0.into_bytes(),
        apns_private_key: Zeroizing::new(
            key.private_key_to_pem_pkcs8()
                .map_err(|_| Error::CertificateRequest)?,
        ),
        apns_topic: apns.2.topic.ok_or(Error::CertificateRequest)?,
        accounts,
    })
}
async fn read(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    protection: &rss_mdm_native_protection::Protector,
    roots: &[Vec<u8>],
    purpose: Purpose,
    revision: i64,
    now: i64,
) -> Result<
    (
        String,
        rss_mdm_native_protection::Plaintext,
        crypto::Certificate,
    ),
    Error,
> {
    use sqlx::Row;
    let row=sqlx::query("SELECT v.* FROM mdm_apple_runtime.versions v JOIN mdm_apple_runtime.heads h USING(tenant_id,purpose) WHERE v.tenant_id=$1::uuid AND v.purpose=$2 AND v.revision=$3 AND v.selected AND NOT v.revoked AND (v.purpose='managed_account' OR h.desired_revision=v.revision)")
        .bind(tenant).bind(purpose.name()).bind(revision).fetch_optional(c).await.map_err(db)?.ok_or(Error::Conflict)?;
    let key: Uuid = row.try_get("key_id").map_err(db)?;
    let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
    let private = protection
        .open_bytes(&sealed, &aad(tenant, purpose, revision, key)?)
        .map_err(|_| Error::Conflict)?;
    let pem: String = row.try_get("certificate").map_err(db)?;
    let validated = crypto::certificate(purpose, &pem, private.expose(), roots, now)?;
    let digest: String = row.try_get("certificate_digest").map_err(db)?;
    if digest != validated.digest {
        return Err(Error::Conflict);
    }
    Ok((pem, private, validated))
}
