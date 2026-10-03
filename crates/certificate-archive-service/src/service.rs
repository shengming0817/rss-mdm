//! Single owner for archive behavior. The App owns the shared pool and task lifecycle.
use crate::{
    model::Bundle,
    protection::{self, Cache, Key},
    store::{self, Mutation},
    *,
};
use rss_mdm_audit_integration::{AuditStore, RequestAudit};
use rss_mdm_authorization_service::{Permission as P, context::AuthorizedPrincipal};
use sqlx::{PgPool, Row};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Result<i64, Error>;
    fn now(&self) -> Instant;
}
pub struct Archive {
    pool: PgPool,
    audit: Arc<AuditStore>,
    clock: Arc<dyn Clock>,
    cache: Cache,
    workers: Arc<tokio::sync::Semaphore>,
}
impl Archive {
    pub fn new(pool: PgPool, audit: Arc<AuditStore>, clock: Arc<dyn Clock>) -> Self {
        Self {
            pool,
            audit,
            clock,
            cache: Cache::default(),
            workers: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
    /// Purge unused plaintext unlocks and wait for bounded blocking work at shutdown.
    pub fn registration(self: Arc<Self>) -> rss_runtime::ManagedTaskRegistration {
        let (task, _) = rss_runtime::ManagedTask::prepare(
            "certificate-archive-secrets",
            Duration::from_secs(20),
        );
        task.into_registration(move|stop|async move{
            loop {tokio::select!{()=stop.cancelled()=>break,()=tokio::time::sleep(Duration::from_millis(250))=>{}}
                self.cache.purge(self.clock.as_ref()).map_err(rss_runtime::ShutdownError::new)?;
            }
            let permits=self.workers.clone().acquire_many_owned(2).await.map_err(|_|rss_runtime::ShutdownError::new(Error::Storage))?;
            self.cache.clear().map_err(rss_runtime::ShutdownError::new)?;drop(permits);Ok(())
        })
    }
    async fn work<R: Send + 'static>(
        &self,
        job: impl FnOnce() -> Result<R, Error> + Send + 'static,
    ) -> Result<R, Error> {
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Limited)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            job()
        })
        .await
        .map_err(|_| Error::Storage)?
    }
    async fn vault(&self, p: &AuthorizedPrincipal) -> Result<Option<store::Vault>, Error> {
        let mut tx = store::begin(&self.pool, p.tenant_id()).await?;
        let result = store::vault(&mut tx, p.tenant_id()).await?;
        tx.rollback().await?;
        Ok(result)
    }
    async fn key(&self, p: &AuthorizedPrincipal) -> Result<(Key, i64), Error> {
        p.manage(P::CertificateArchiveUnlock)?;
        let vault = self.vault(p).await?.ok_or(Error::Locked)?;
        let (key, _) = self.cache.get(p, vault.generation, self.clock.as_ref())?;
        Ok((key, vault.generation))
    }
    pub async fn state(&self, p: &AuthorizedPrincipal) -> Result<VaultState, Error> {
        p.manage(P::CertificateArchiveRead)?;
        let vault = self.vault(p).await?;
        let generation = vault.as_ref().map(|v| v.generation).unwrap_or(0);
        let until = if p.manage(P::CertificateArchiveUnlock).is_ok() {
            self.cache
                .get(p, generation, self.clock.as_ref())
                .ok()
                .map(|(_, u)| u)
        } else {
            None
        };
        Ok(VaultState {
            initialized: vault.is_some(),
            generation,
            unlocked_until: until,
        })
    }
    pub async fn unlock(
        &self,
        p: &AuthorizedPrincipal,
        input: PasswordInput,
    ) -> Result<VaultState, Error> {
        p.manage(P::CertificateArchiveUnlock)?;
        let vault = self.vault(p).await?.ok_or(Error::Locked)?;
        let tenant = p.tenant_id().to_owned();
        let generation = vault.generation;
        let key = self
            .work(move || {
                let kek = protection::derive(&input.password, &vault.salt)?;
                protection::unwrap(&tenant, generation, kek.as_ref(), &vault.wrapped)
            })
            .await?;
        p.check_live()?;
        if self
            .vault(p)
            .await?
            .is_none_or(|v| v.generation != generation)
        {
            return Err(Error::Conflict);
        }
        let until = self.cache.put(p, generation, key, self.clock.as_ref())?;
        Ok(VaultState {
            initialized: true,
            generation,
            unlocked_until: Some(until),
        })
    }
    pub fn lock(&self, p: &AuthorizedPrincipal) -> Result<(), Error> {
        p.check_live()?;
        self.cache.lock(p)
    }
    pub async fn initialize(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: PasswordInput,
        audit: &RequestAudit,
    ) -> Result<Receipt, Error> {
        p.manage(P::CertificateArchiveWrite)?;
        p.manage(P::CertificateArchiveUnlock)?;
        let old = self.vault(p).await?;
        let tenant = p.tenant_id().to_owned();
        let (salt, wrapped, digest) = self
            .work(move || {
                let salt = match &old {
                    Some(v) => v.salt.clone(),
                    None => protection::random::<16>()?.to_vec(),
                };
                let kek = protection::derive(&input.password, &salt)?;
                let key = match &old {
                    Some(v) => protection::unwrap(&tenant, v.generation, kek.as_ref(), &v.wrapped)?,
                    None => Arc::new(Zeroizing::new(protection::random::<32>()?)),
                };
                let digest = protection::protector(kek.as_ref())?
                    .mac(
                        b"initialize",
                        &protection::aad(&tenant, "vault", "certificate-archive.operation/v1")?,
                    )
                    .map_err(|_| Error::Integrity)?;
                let wrapped = protection::wrap(&tenant, 1, kek.as_ref(), key.as_ref().as_ref())?;
                Ok((salt, wrapped, digest))
            })
            .await?;
        store::write(
            &self.audit,
            p,
            id,
            "certificate_archive_initialize",
            digest,
            Mutation::Password {
                expected: 0,
                salt,
                wrapped,
            },
            audit,
        )
        .await
    }
    pub async fn change_password(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: ChangePassword,
        audit: &RequestAudit,
    ) -> Result<Receipt, Error> {
        p.manage(P::CertificateArchiveWrite)?;
        p.manage(P::CertificateArchiveUnlock)?;
        let vault = self.vault(p).await?.ok_or(Error::Locked)?;
        let expected = vault.generation;
        let tenant = p.tenant_id().to_owned();
        let mut tx = store::begin(&self.pool, p.tenant_id()).await?;
        let old_operation = store::operation(&mut tx, p, id).await?;
        tx.rollback().await?;
        let can_recover =
            old_operation.is_some_and(|(_, r)| r.action == "certificate_archive_password_change");
        let (salt, wrapped, digest) = self
            .work(move || {
                let kek = protection::derive(&input.old_password, &vault.salt)?;
                let key = match protection::unwrap(&tenant, expected, kek.as_ref(), &vault.wrapped)
                {
                    Ok(key) => key,
                    Err(Error::Password) if can_recover => {
                        let current = protection::derive(&input.new_password, &vault.salt)?;
                        protection::unwrap(&tenant, expected, current.as_ref(), &vault.wrapped)?
                    }
                    Err(e) => return Err(e),
                };
                let salt = protection::random::<16>()?;
                let next = protection::derive(&input.new_password, &salt)?;
                let digest = request_digest(
                    key.as_ref().as_ref(),
                    &tenant,
                    &(
                        "password_change",
                        input.old_password.as_str(),
                        input.new_password.as_str(),
                    ),
                )?;
                let wrapped = protection::wrap(
                    &tenant,
                    expected.checked_add(1).ok_or(Error::Conflict)?,
                    next.as_ref(),
                    key.as_ref().as_ref(),
                )?;
                Ok((salt.to_vec(), wrapped, digest))
            })
            .await?;
        let result = store::write(
            &self.audit,
            p,
            id,
            "certificate_archive_password_change",
            digest,
            Mutation::Password {
                expected,
                salt,
                wrapped,
            },
            audit,
        )
        .await;
        // Unknown commits also lock this process; every other process checks the DB generation.
        self.cache.invalidate(p.tenant_id())?;
        result
    }
    async fn read_material(
        &self,
        p: &AuthorizedPrincipal,
        id: VersionRef,
        key: &Key,
    ) -> Result<(Version, Bundle), Error> {
        if id.entry_id.is_nil() || id.version <= 0 {
            return Err(Error::Malformed);
        }
        let mut tx = store::begin(&self.pool, p.tenant_id()).await?;
        let (version, sealed) = store::version(&mut tx, p.tenant_id(), id).await?;
        tx.rollback().await?;
        let plain = protection::protector(key.as_ref().as_ref())?
            .open_bytes(
                &sealed,
                &protection::material_aad(p.tenant_id(), id.entry_id, id.version)?,
            )
            .map_err(|_| Error::Integrity)?;
        let bundle = serde_json::from_slice(plain.expose()).map_err(|_| Error::Integrity)?;
        Ok((version, bundle))
    }
    pub async fn import(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: Import,
        audit: &RequestAudit,
    ) -> Result<Receipt, Error> {
        p.manage(P::CertificateArchiveWrite)?;
        validate_entry(input.entry_id, input.expected_revision)?;
        input.metadata.validate()?;
        let (key, generation) = self.key(p).await?;
        let digest = request_digest(key.as_ref().as_ref(), p.tenant_id(), &("import", &input))?;
        if let Some(receipt) = self
            .existing(p, id, &digest, "certificate_archive_import", audit)
            .await?
        {
            return Ok(receipt);
        }
        let request = match input.request_version {
            None => None,
            Some(reference) => {
                p.manage(P::CertificateArchiveRead)?;
                Some(self.read_material(p, reference, &key).await?.0)
            }
        };
        let entry = input.entry_id;
        let expected = input.expected_revision;
        let metadata = input.metadata.clone();
        let (bundle, facts) = self
            .work(move || crate::materials::parse(&input.files))
            .await?;
        if let Some(request) = request {
            crate::materials::check_request(&request.facts, &facts)?;
        }
        self.save_material(
            p,
            id,
            "certificate_archive_import",
            digest,
            key,
            generation,
            entry,
            expected,
            metadata,
            bundle,
            facts,
            "import",
            audit,
        )
        .await
    }
    pub async fn generate(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: Generate,
        audit: &RequestAudit,
    ) -> Result<Receipt, Error> {
        p.manage(P::CertificateArchiveWrite)?;
        validate_entry(input.entry_id, input.expected_revision)?;
        input.metadata.validate()?;
        let (key, generation) = self.key(p).await?;
        let digest = request_digest(key.as_ref().as_ref(), p.tenant_id(), &("generate", &input))?;
        if let Some(receipt) = self
            .existing(p, id, &digest, "certificate_archive_generate", audit)
            .await?
        {
            return Ok(receipt);
        }
        let issuer = match input.issuer {
            None => None,
            Some(reference) => {
                p.manage(P::CertificateArchiveRead)?;
                Some(self.read_material(p, reference, &key).await?.1)
            }
        };
        let entry = input.entry_id;
        let expected = input.expected_revision;
        let metadata = input.metadata.clone();
        let now = self.clock.unix_seconds()?;
        let (bundle, facts) = self
            .work(move || crate::generation::generate(&input, issuer.as_ref(), now))
            .await?;
        self.save_material(
            p,
            id,
            "certificate_archive_generate",
            digest,
            key,
            generation,
            entry,
            expected,
            metadata,
            bundle,
            facts,
            "generate",
            audit,
        )
        .await
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "one explicit material write boundary"
    )]
    async fn save_material(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        action: &'static str,
        digest: [u8; 32],
        key: Key,
        generation: i64,
        entry: Uuid,
        expected: i64,
        metadata: Metadata,
        bundle: Bundle,
        facts: Vec<MaterialFacts>,
        source: &'static str,
        audit: &RequestAudit,
    ) -> Result<Receipt, Error> {
        self.cache.get(p, generation, self.clock.as_ref())?;
        let plain = Zeroizing::new(serde_json::to_vec(&bundle).map_err(|_| Error::Integrity)?);
        if plain.len() > 3 * 1024 * 1024 - 68
            || serde_json::to_vec(&facts)
                .map_err(|_| Error::Integrity)?
                .len()
                > 262144
        {
            return Err(Error::Malformed);
        }
        let sealed = protection::protector(key.as_ref().as_ref())?
            .seal_bytes(
                &plain,
                &protection::material_aad(
                    p.tenant_id(),
                    entry,
                    expected.checked_add(1).ok_or(Error::Conflict)?,
                )?,
            )
            .map_err(|_| Error::Integrity)?;
        store::write(
            &self.audit,
            p,
            id,
            action,
            digest,
            Mutation::Material {
                generation,
                entry,
                expected,
                metadata,
                facts,
                sealed,
                source,
            },
            audit,
        )
        .await
    }
    pub async fn change_metadata(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        entry: Uuid,
        input: ChangeMetadata,
        audit: &RequestAudit,
    ) -> Result<Receipt, Error> {
        p.manage(P::CertificateArchiveWrite)?;
        validate_entry(entry, input.expected_revision)?;
        input.metadata.validate()?;
        let (key, generation) = self.key(p).await?;
        let digest = request_digest(
            key.as_ref().as_ref(),
            p.tenant_id(),
            &("metadata", entry, &input),
        )?;
        if let Some(receipt) = self
            .existing(p, id, &digest, "certificate_archive_metadata", audit)
            .await?
        {
            return Ok(receipt);
        }
        let history = self.history(p, entry, None).await?;
        let latest = history.first().ok_or(Error::NotFound)?;
        let (previous, bundle) = self
            .read_material(
                p,
                VersionRef {
                    entry_id: entry,
                    version: latest.version,
                },
                &key,
            )
            .await?;
        self.save_material(
            p,
            id,
            "certificate_archive_metadata",
            digest,
            key,
            generation,
            entry,
            input.expected_revision,
            input.metadata,
            bundle,
            previous.facts,
            "metadata",
            audit,
        )
        .await
    }
    async fn existing(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        digest: &[u8; 32],
        action: &'static str,
        audit: &RequestAudit,
    ) -> Result<Option<Receipt>, Error> {
        let mut tx = store::begin(&self.pool, p.tenant_id()).await?;
        let result = store::operation(&mut tx, p, id).await?;
        tx.rollback().await?;
        match result {
            Some((old, receipt)) => {
                if old.as_slice() != digest || receipt.action != action {
                    return Err(Error::Conflict);
                }
                Ok(Some(
                    store::write(&self.audit, p, id, action, *digest, Mutation::Replay, audit)
                        .await?,
                ))
            }
            None => Ok(None),
        }
    }
    pub async fn operation(&self, p: &AuthorizedPrincipal, id: Uuid) -> Result<Receipt, Error> {
        p.manage(P::CertificateArchiveRead)?;
        let mut tx = store::begin(&self.pool, p.tenant_id()).await?;
        let result = store::operation(&mut tx, p, id)
            .await?
            .ok_or(Error::NotFound)?
            .1;
        tx.rollback().await?;
        Ok(result)
    }
    pub async fn list(&self, p: &AuthorizedPrincipal, after: Option<Uuid>) -> Result<Page, Error> {
        p.manage(P::CertificateArchiveRead)?;
        let mut tx = store::begin(&self.pool, p.tenant_id()).await?;
        let settings = store::settings(&mut tx, p.tenant_id()).await?;
        let rows=sqlx::query("SELECT e.id::text,e.revision,e.retired,e.recommended_version,v.entry_id::text,v.version,v.actor::text,v.instance::text,v.operation_id::text,v.created_at,v.metadata::text,v.facts::text,v.source FROM mdm_certificate_archive.entries e JOIN LATERAL(SELECT * FROM mdm_certificate_archive.versions x WHERE x.tenant_id=e.tenant_id AND x.entry_id=e.id ORDER BY x.version DESC LIMIT 1)v ON true WHERE e.tenant_id=$1::uuid AND ($2::uuid IS NULL OR e.id>$2::uuid) ORDER BY e.id LIMIT 51").bind(p.tenant_id()).bind(after.map(|id|id.to_string())).fetch_all(&mut *tx).await?;
        let more = rows.len() > 50;
        let items = rows
            .iter()
            .take(50)
            .map(|r| {
                Ok(Entry {
                    id: Uuid::parse_str(&r.try_get::<String, _>("id")?)
                        .map_err(|_| Error::Integrity)?,
                    revision: r.try_get("revision")?,
                    retired: r.try_get("retired")?,
                    recommended_version: r.try_get("recommended_version")?,
                    latest: store::decode_version(r)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let next_after = if more {
            items.last().map(|v| v.id)
        } else {
            None
        };
        let now = self.clock.unix_seconds()?;
        let warning = now + i64::from(settings.value.reminder_days) * 86400;
        let alerts=sqlx::query(r#"WITH current_versions AS (
 SELECT e.id,v.facts FROM mdm_certificate_archive.entries e JOIN LATERAL(SELECT facts FROM mdm_certificate_archive.versions x WHERE x.tenant_id=e.tenant_id AND x.entry_id=e.id ORDER BY version DESC LIMIT 1)v ON true WHERE e.tenant_id=$1::uuid AND NOT e.retired
 ), times AS (
 SELECT v.id, bool_or((cert->>'notAfter')::bigint<=$2) expired, bool_or((cert->>'notBefore')::bigint>$2) not_yet_valid, bool_or((cert->>'notAfter')::bigint<=$3) expiring FROM current_versions v CROSS JOIN LATERAL jsonb_array_elements(v.facts) f CROSS JOIN LATERAL jsonb_array_elements(f->'certificates') cert GROUP BY v.id)
 SELECT count(*) FILTER(WHERE expired) expired,count(*) FILTER(WHERE NOT expired AND NOT not_yet_valid AND expiring) expiring,count(*) FILTER(WHERE NOT expired AND not_yet_valid) not_yet_valid FROM times"#).bind(p.tenant_id()).bind(now).bind(warning).fetch_one(&mut *tx).await?;
        let alerts = Alerts {
            expired: alerts.try_get("expired")?,
            expiring: alerts.try_get("expiring")?,
            not_yet_valid: alerts.try_get("not_yet_valid")?,
        };
        tx.rollback().await?;
        Ok(Page {
            tenant_id: p.tenant_id().into(),
            items,
            next_after,
            as_of: now,
            reminder_days: settings.value.reminder_days,
            alerts,
        })
    }
    pub async fn history(
        &self,
        p: &AuthorizedPrincipal,
        entry: Uuid,
        before: Option<i64>,
    ) -> Result<Vec<Version>, Error> {
        p.manage(P::CertificateArchiveRead)?;
        if entry.is_nil() || before.is_some_and(|v| v <= 0) {
            return Err(Error::Malformed);
        }
        let mut tx = store::begin(&self.pool, p.tenant_id()).await?;
        let rows=sqlx::query("SELECT entry_id::text,version,actor::text,instance::text,operation_id::text,created_at,metadata::text,facts::text,source FROM mdm_certificate_archive.versions WHERE tenant_id=$1::uuid AND entry_id=$2::uuid AND ($3::bigint IS NULL OR version<$3) ORDER BY version DESC LIMIT 50").bind(p.tenant_id()).bind(entry.to_string()).bind(before).fetch_all(&mut *tx).await?;
        let values = rows
            .iter()
            .map(store::decode_version)
            .collect::<Result<_, _>>()?;
        tx.rollback().await?;
        Ok(values)
    }
    pub async fn export(
        &self,
        p: &AuthorizedPrincipal,
        operation: Uuid,
        id: VersionRef,
        audit: &RequestAudit,
    ) -> Result<Export, Error> {
        p.manage(P::CertificateArchiveExport)?;
        let (key, generation) = self.key(p).await?;
        let (_, bundle) = self.read_material(p, id, &key).await?;
        let digest = request_digest(key.as_ref().as_ref(), p.tenant_id(), &("export", id))?;
        store::write(
            &self.audit,
            p,
            operation,
            "certificate_archive_export",
            digest,
            Mutation::Export { generation, id },
            audit,
        )
        .await?;
        self.cache.get(p, generation, self.clock.as_ref())?;
        Ok(Export {
            entry_id: id.entry_id,
            version: id.version,
            files: bundle.files,
        })
    }
    pub async fn settings(&self, p: &AuthorizedPrincipal) -> Result<SettingsView, Error> {
        p.manage(P::CertificateArchiveRead)?;
        let mut tx = store::begin(&self.pool, p.tenant_id()).await?;
        let result = store::settings(&mut tx, p.tenant_id()).await?;
        tx.rollback().await?;
        Ok(result)
    }
    pub async fn change_settings(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: ChangeSettings,
        audit: &RequestAudit,
    ) -> Result<Receipt, Error> {
        p.manage(P::CertificateArchiveWrite)?;
        input.value.validate()?;
        validate_revision(input.expected_revision)?;
        let digest = public_digest(&("settings", input.expected_revision, &input.value))?;
        store::write(
            &self.audit,
            p,
            id,
            "certificate_archive_settings",
            digest,
            Mutation::Settings {
                expected: input.expected_revision,
                value: input.value,
            },
            audit,
        )
        .await
    }
    pub async fn manage(
        &self,
        p: &AuthorizedPrincipal,
        operation: Uuid,
        entry: Uuid,
        input: ManageEntry,
        audit: &RequestAudit,
    ) -> Result<Receipt, Error> {
        p.manage(P::CertificateArchiveWrite)?;
        validate_entry(entry, input.expected_revision)?;
        if input.expected_revision == 0 || input.recommended_version.is_some_and(|v| v <= 0) {
            return Err(Error::Malformed);
        }
        let digest = public_digest(&("manage", entry, &input))?;
        store::write(
            &self.audit,
            p,
            operation,
            "certificate_archive_manage",
            digest,
            Mutation::Manage { entry, input },
            audit,
        )
        .await
    }
}
fn validate_revision(v: i64) -> Result<(), Error> {
    if !(0..i64::MAX).contains(&v) {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
fn validate_entry(id: Uuid, v: i64) -> Result<(), Error> {
    if id.is_nil() {
        return Err(Error::Malformed);
    }
    validate_revision(v)
}
fn request_digest(
    key: &[u8],
    tenant: &str,
    input: &impl serde::Serialize,
) -> Result<[u8; 32], Error> {
    let bytes = Zeroizing::new(serde_json::to_vec(input).map_err(|_| Error::Malformed)?);
    protection::protector(key)?
        .mac(
            &bytes,
            &protection::aad(tenant, "request", "certificate-archive.operation/v1")?,
        )
        .map_err(|_| Error::Integrity)
}
fn public_digest(input: &impl serde::Serialize) -> Result<[u8; 32], Error> {
    ring::digest::digest(
        &ring::digest::SHA256,
        &serde_json::to_vec(input).map_err(|_| Error::Malformed)?,
    )
    .as_ref()
    .try_into()
    .map_err(|_| Error::Integrity)
}
