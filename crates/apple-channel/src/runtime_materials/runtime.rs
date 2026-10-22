//! Exact selected versions consumed by the host; no fallback to startup credential files.
use super::*;
use std::collections::BTreeMap;
/// Host-owned immutable application input. Values are material revisions, never filesystem paths.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub apns: Option<i64>,
    pub profile: Option<i64>,
    #[serde(default)]
    pub accounts: BTreeMap<String, i64>,
}
/// Material readiness is separate from persistence and integrity failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterialFailure {
    NotSelected,
    Missing,
    Revoked,
    Expired,
    VersionMismatch,
    Invalid,
}
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("Apple runtime material unavailable: {0:?}")]
    Blocked(MaterialFailure),
    #[error(transparent)]
    Fatal(#[from] Error),
}
/// Verified material held only by the running owner. This type deliberately has no Debug/Serialize.
pub struct Loaded {
    pub binding: Binding,
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
) -> Result<Loaded, LoadError> {
    let apns_revision = selection
        .apns
        .ok_or(LoadError::Blocked(MaterialFailure::NotSelected))?;
    let profile_revision = selection
        .profile
        .ok_or(LoadError::Blocked(MaterialFailure::NotSelected))?;
    if apns_revision < 1 || profile_revision < 1 || selection.accounts.len() > 16 {
        return Err(Error::Malformed.into());
    }
    let tenant = tenant.to_string();
    let mut tx = store.material_snapshot(&tenant).await?;
    let result = async {
        let apns = read(
            &mut tx,
            &tenant,
            protection,
            roots,
            Purpose::Apns,
            apns_revision,
            now,
        )
        .await?;
        let profile = read(
            &mut tx,
            &tenant,
            protection,
            roots,
            Purpose::Profile,
            profile_revision,
            now,
        )
        .await?;
        let mut records = vec![
            (Purpose::Apns, apns_revision, apns.2.digest.clone()),
            (Purpose::Profile, profile_revision, profile.2.digest.clone()),
        ];
        let mut expires = apns.2.expires.min(profile.2.expires);
        let profile = rss_mdm_certificate::apple::ProfileSigner::from_bytes(
            profile.0.as_bytes(),
            profile.1.expose(),
            now,
        )?;
        let mut accounts = BTreeMap::new();
        for (id, revision) in &selection.accounts {
            if !super::account_alias_valid(id) {
                return Err(Error::Malformed.into());
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
            records.push((
                Purpose::ManagedAccount,
                *revision,
                material.2.digest.clone(),
            ));
            expires = expires.min(material.2.expires);
            accounts.insert(
                id.clone(),
                rss_mdm_certificate::apple::ManagedAccountTokenSigner::from_bytes(
                    material.0.as_bytes(),
                    material.1.expose(),
                    now,
                )?,
            );
        }
        let key = openssl::pkey::PKey::private_key_from_pkcs8(apns.1.expose())
            .map_err(|_| Error::CertificateRequest)?;
        Ok(Loaded {
            binding: Binding { records, expires },
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
    .await;
    tx.rollback().await.map_err(db)?;
    result
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
    LoadError,
> {
    use sqlx::Row;
    let row=sqlx::query("SELECT v.* FROM mdm_apple_runtime.versions v JOIN mdm_apple_runtime.heads h USING(tenant_id,purpose) WHERE v.tenant_id=$1::uuid AND v.purpose=$2 AND v.revision=$3 ")
        .bind(tenant).bind(purpose.name()).bind(revision).fetch_optional(c).await.map_err(db)?.ok_or(LoadError::Blocked(MaterialFailure::Missing))?;
    if row.try_get::<bool, _>("revoked").map_err(db)? {
        return Err(LoadError::Blocked(MaterialFailure::Revoked));
    }
    if !row.try_get::<bool, _>("selected").map_err(db)? {
        return Err(LoadError::Blocked(MaterialFailure::VersionMismatch));
    }
    let expires: Option<i64> = row.try_get("expires_at").map_err(db)?;
    if expires.is_some_and(|expires| expires <= now) {
        return Err(LoadError::Blocked(MaterialFailure::Expired));
    }
    let key: Uuid = row.try_get("key_id").map_err(db)?;
    let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
    let private = protection
        .open_bytes(&sealed, &aad(tenant, purpose, revision, key)?)
        .map_err(|_| Error::Conflict)?;
    let pem: String = row.try_get("certificate").map_err(db)?;
    let validated = crypto::certificate(purpose, &pem, private.expose(), roots, now)
        .map_err(|_| LoadError::Blocked(MaterialFailure::Invalid))?;
    let digest: String = row.try_get("certificate_digest").map_err(db)?;
    if digest != validated.digest {
        return Err(Error::Conflict.into());
    }
    Ok((pem, private, validated))
}

/// Immutable material identities loaded by this process; desired revision may advance separately.
pub struct Binding {
    records: Vec<(Purpose, i64, String)>,
    expires: i64,
}
impl Binding {
    pub fn valid_at(&self, now: i64) -> bool {
        now > 0 && now < self.expires
    }
    #[cfg(feature = "integration")]
    pub fn fixture(expires: i64) -> Self {
        Self {
            records: Vec::new(),
            expires,
        }
    }
    pub async fn check(&self, store: &crate::Store, tenant: &str, now: i64) -> Result<(), Error> {
        if !self.valid_at(now) {
            return Err(Error::Conflict.into());
        }
        let mut tx = store.material_snapshot(tenant).await?;
        for (purpose, revision, digest) in &self.records {
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple_runtime.versions WHERE tenant_id=$1::uuid AND purpose=$2 AND revision=$3 AND certificate_digest=$4 AND selected AND NOT revoked AND expires_at>$5)")
                .bind(tenant).bind(purpose.name()).bind(revision).bind(digest).bind(now).fetch_one(&mut *tx).await.map_err(db)?;
            if !valid {
                return Err(Error::Conflict.into());
            }
        }
        tx.rollback().await.map_err(db)?;
        Ok(())
    }
}
pub(crate) async fn admit(
    axum::extract::State(app): axum::extract::State<Arc<HttpState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, Error> {
    let apple = app.apple()?;
    apple
        .check_materials(&app.access, &app.identity.tenant().to_string(), now(&app)?)
        .await?;
    Ok(next.run(request).await)
}

impl From<rss_mdm_certificate::Error> for LoadError {
    fn from(error: rss_mdm_certificate::Error) -> Self {
        Self::Fatal(error.into())
    }
}
