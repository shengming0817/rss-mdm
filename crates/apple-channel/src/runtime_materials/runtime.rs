//! Exact selected versions consumed by the host; no fallback to startup credential files.
use super::*;
use std::collections::BTreeMap;
/// Exact owner-selected material revisions for one operation snapshot.
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
    pub identity_seed: crate::IdentitySeed,
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
    now: i64,
) -> Result<Loaded, LoadError> {
    let tenant = tenant.to_string();
    let mut tx = store.material_snapshot(&tenant).await?;
    let heads:Vec<(String,Option<i64>)>=sqlx::query_as("SELECT purpose,desired_revision FROM mdm_apple_runtime.heads WHERE tenant_id=$1::uuid ORDER BY purpose").bind(&tenant).fetch_all(&mut *tx).await.map_err(db)?;
    let revision = |purpose: &str| {
        heads
            .iter()
            .find(|(name, _)| name == purpose)
            .and_then(|(_, revision)| *revision)
            .ok_or(LoadError::Blocked(MaterialFailure::NotSelected))
    };
    let apns_revision = revision("apns")?;
    let profile_revision = revision("profile")?;
    let account_bindings:Vec<(String,i64)>=sqlx::query_as("SELECT alias,revision FROM mdm_apple_runtime.account_bindings WHERE tenant_id=$1::uuid ORDER BY alias").bind(&tenant).fetch_all(&mut *tx).await.map_err(db)?;
    let seed: Option<(String, String)> = sqlx::query_as(
        "SELECT challenge_id,notify_id FROM mdm_apple_runtime.identity WHERE tenant_id=$1::uuid",
    )
    .bind(&tenant)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    let (challenge_id, notify_id) = seed.ok_or(LoadError::Blocked(MaterialFailure::NotSelected))?;
    let identity_seed = crate::IdentitySeed {
        challenge_id,
        notify_id,
    };
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
        for (id, revision) in &account_bindings {
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
            identity_seed,
            binding: Binding {
                records,
                expires,
                selection: Selection {
                    apns: Some(apns_revision),
                    profile: Some(profile_revision),
                    accounts: account_bindings.iter().cloned().collect(),
                },
            },
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
/// Inspect only the selected account signer materials within the caller's tenant snapshot.
pub(crate) async fn account_keys_on(
    app: &HttpState,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    now: i64,
) -> Result<Vec<String>, Error> {
    let bindings:Vec<(String,i64)>=sqlx::query_as("SELECT alias,revision FROM mdm_apple_runtime.account_bindings WHERE tenant_id=$1::uuid ORDER BY alias").bind(tenant).fetch_all(&mut *c).await.map_err(db)?;
    let mut keys = Vec::new();
    for (alias, revision) in bindings {
        match read(
            c,
            tenant,
            &app.protection,
            &app.material_roots,
            Purpose::ManagedAccount,
            revision,
            now,
        )
        .await
        {
            Ok((pem, private, _)) => {
                rss_mdm_certificate::apple::ManagedAccountTokenSigner::from_bytes(
                    pem.as_bytes(),
                    private.expose(),
                    now,
                )?;
                keys.push(alias);
            }
            Err(LoadError::Blocked(_)) => {}
            Err(LoadError::Fatal(error)) => return Err(error),
        }
    }
    Ok(keys)
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
    let key: Uuid = row.try_get("key_id").map_err(db)?;
    let sealed: Vec<u8> = row.try_get("private_key").map_err(db)?;
    let private = protection
        .open_bytes(&sealed, &aad(tenant, purpose, revision, key)?)
        .map_err(|_| Error::Conflict)?;
    let pem: Option<String> = row.try_get("certificate").map_err(db)?;
    let digest: Option<String> = row.try_get("certificate_digest").map_err(db)?;
    let (pem, digest) = pem
        .zip(digest)
        .ok_or(LoadError::Blocked(MaterialFailure::Missing))?;
    if digest != crypto::persisted_digest(&pem, private.expose())? {
        return Err(Error::Conflict.into());
    }
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
    let validated = crypto::certificate(purpose, &pem, private.expose(), roots, now)
        .map_err(|_| LoadError::Blocked(MaterialFailure::Invalid))?;
    Ok((pem, private, validated))
}

/// Immutable material identities loaded by this process; desired revision may advance separately.
pub struct Binding {
    selection: Selection,
    records: Vec<(Purpose, i64, String)>,
    expires: i64,
}
impl Binding {
    pub fn selection(&self) -> Selection {
        self.selection.clone()
    }

    pub fn valid_at(&self, now: i64) -> bool {
        now > 0 && now < self.expires
    }

    pub async fn check(&self, store: &crate::Store, tenant: &str, now: i64) -> Result<(), Error> {
        if !self.valid_at(now) {
            return Err(Error::Conflict);
        }
        let mut tx = store.material_snapshot(tenant).await?;
        for (purpose, revision, digest) in &self.records {
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple_runtime.versions WHERE tenant_id=$1::uuid AND purpose=$2 AND revision=$3 AND certificate_digest=$4 AND selected AND NOT revoked AND expires_at>$5)")
                .bind(tenant).bind(purpose.name()).bind(revision).bind(digest).bind(now).fetch_one(&mut *tx).await.map_err(db)?;
            if !valid {
                return Err(Error::Conflict);
            }
        }
        tx.rollback().await.map_err(db)?;
        Ok(())
    }
}
impl From<rss_mdm_certificate::Error> for LoadError {
    fn from(error: rss_mdm_certificate::Error) -> Self {
        Self::Fatal(error.into())
    }
}

/// Shared physical transports. An operation loads only its immutable Apple material snapshot.
/// Ordinary tenants without selected APNs material allocate no transport.
pub struct Runtime {
    origin: String,
    pub webhooks: Option<Arc<rss_mdm_pki_service::scep::Verifier>>,
    push: tokio::sync::Mutex<BTreeMap<String, (String, Arc<crate::push::Push>)>>,
}
impl Runtime {
    pub fn new(origin: String, webhooks: Option<Arc<rss_mdm_pki_service::scep::Verifier>>) -> Self {
        Self {
            origin,
            webhooks,
            push: Default::default(),
        }
    }
    pub async fn load(
        &self,
        app: &HttpState,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
    ) -> Result<Arc<crate::Apple>, Error> {
        let now = now(app)?;
        let trust = app
            .pki
            .current(execution, rss_mdm_agent_wire::pki::Purpose::Apple, now)
            .await?;
        if trust.public().map_err(|_| Error::Conflict)?.origin != self.origin {
            return Err(Error::Conflict);
        }
        let authority = rss_mdm_device_trust::apple::AppleDeviceTrust::from_trust(trust)
            .map_err(|_| Error::Conflict)?;
        let materials = match load(
            &app.access,
            execution.tenant(),
            &app.protection,
            &app.material_roots,
            now,
        )
        .await
        {
            Ok(materials) => materials,
            Err(LoadError::Blocked(_)) => {
                self.push
                    .lock()
                    .await
                    .remove(&execution.tenant().to_string());
                return Err(Error::Unsupported);
            }
            Err(LoadError::Fatal(error)) => return Err(error),
        };

        let digest = materials
            .binding
            .records
            .iter()
            .find(|(purpose, _, _)| *purpose == Purpose::Apns)
            .ok_or(Error::Conflict)?
            .2
            .clone();
        let push = {
            let mut transports = self.push.lock().await;
            if let Some((old, push)) = transports.get(&execution.tenant().to_string())
                && *old == digest
            {
                push.clone()
            } else {
                let push = Arc::new(crate::push::Push::from_bytes(
                    materials.apns_topic.clone(),
                    &materials.apns_certificate,
                    &materials.apns_private_key,
                    app.clock.clone(),
                )?);
                transports.insert(execution.tenant().to_string(), (digest, push.clone()));
                push
            }
        };
        let mut apple = crate::Apple::new(
            app.protection.clone(),
            crate::Config {
                management: crate::Origin {
                    origin: self.origin.clone(),
                },
                apns_topic: materials.apns_topic,
                identity_seed: materials.identity_seed,
            },
            authority,
            materials.profile,
            push,
            materials.binding,
            app.providers.clone(),
        )
        .with_credential_receipts(app.credential_receipts.clone())
        .with_account_keys(materials.accounts);
        let mut observed = app
            .access
            .begin_read(&execution.tenant().to_string())
            .await?;
        apple.push_available=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM mdm_apple.channels WHERE tenant_id=$1::uuid AND state='active' AND (push_outcome='rejected' OR push_failures>=3))").bind(execution.tenant().to_string()).fetch_one(&mut *observed).await.map_err(db)?;
        observed.rollback().await.map_err(db)?;
        Ok(Arc::new(apple))
    }
}
